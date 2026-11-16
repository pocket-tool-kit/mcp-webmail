"""In-memory IMAP double and tiny TLS POP3/SMTP servers for end-to-end tests."""
import base64
import datetime
import socket
import socketserver
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class FakeIMAP:
    """Stateful stand-in for imapclient.IMAPClient covering the calls the app makes."""

    def __init__(self, folders, capabilities=("MOVE", "UIDPLUS")):
        # folders: name -> {"flags": (b"\\Sent",), "messages": {uid: [raw, set(flags)]}}
        self.folders = {name: {"flags": tuple(box.get("flags", ())), "uidvalidity": box.get("uidvalidity", 1),
                               "messages": {u: [m[0], set(m[1])] for u, m in box.get("messages", {}).items()}}
                        for name, box in folders.items()}
        self.capabilities = set(capabilities)
        self.selected = None
        self.readonly = True
        self.logins = 0
        self.oauth = None

    # -- helpers for assertions
    def uids(self, folder):
        return sorted(self.folders[folder]["messages"])

    def flags(self, folder, uid):
        return self.folders[folder]["messages"][uid][1]

    def raw(self, folder, uid):
        return self.folders[folder]["messages"][uid][0]

    def _next_uid(self, folder):
        return max(self.folders[folder]["messages"], default=0) + 1

    # -- IMAPClient surface
    def list_folders(self):
        return [(box["flags"], b"/", name) for name, box in self.folders.items()]

    def has_capability(self, name):
        return name in self.capabilities

    def select_folder(self, folder, readonly=False):
        if folder not in self.folders:
            raise ValueError("no such folder")
        self.selected, self.readonly = folder, readonly
        return {b"UIDVALIDITY": self.folders[folder]["uidvalidity"]}

    def _box(self):
        return self.folders[self.selected]["messages"]

    def search(self, criteria):
        return sorted(self._box())

    def fetch(self, uids, fields):
        result = {}
        for uid in uids:
            if uid not in self._box():
                continue
            raw, flags = self._box()[uid]
            if fields == ["FLAGS"]:
                result[uid] = {b"FLAGS": tuple(flags)}
            elif fields == ["RFC822.SIZE"]:
                result[uid] = {b"RFC822.SIZE": len(raw)}
            else:
                result[uid] = {b"BODY[]": raw}
        return result

    def append(self, folder, raw, flags=()):
        self.folders[folder]["messages"][self._next_uid(folder)] = [raw, set(flags)]

    def _writable(self):
        assert not self.readonly, "mutation on a read-only SELECT"

    def add_flags(self, uids, flags, silent=False):
        self._writable()
        for uid in uids:
            self._box()[uid][1].update(flags)

    def remove_flags(self, uids, flags, silent=False):
        self._writable()
        for uid in uids:
            self._box()[uid][1].difference_update(flags)

    def copy(self, uids, target):
        for uid in uids:
            raw, flags = self._box()[uid]
            self.folders[target]["messages"][self._next_uid(target)] = [raw, set(flags)]

    def move(self, uids, target):
        self._writable()
        assert "MOVE" in self.capabilities
        self.copy(uids, target)
        for uid in uids:
            del self._box()[uid]

    def expunge(self, messages=None):
        self._writable()
        for uid in list(self._box()):
            if b"\\Deleted" in self._box()[uid][1] and (messages is None or uid in messages):
                del self._box()[uid]

    def logout(self):
        pass


def make_certificate(directory):
    """Self-signed certificate for localhost; returns (cert path, key path)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


class _TLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, handler, cert, key):
        super().__init__(("127.0.0.1", 0), handler)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)

    def get_request(self):
        sock, address = self.socket.accept()
        return self.context.wrap_socket(sock, server_side=True), address

    def handle_error(self, request, client_address):
        pass  # clients closing abruptly are part of some tests

    def start(self):
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self.server_address[1]


class POP3Handler(socketserver.StreamRequestHandler):
    def handle(self):
        server = self.server
        send = lambda line: self.wfile.write(line.encode() + b"\r\n")  # noqa: E731
        send("+OK ready")
        user = None
        while True:
            line = self.rfile.readline().decode("utf-8", "replace").strip()
            if not line:
                return
            command, _, argument = line.partition(" ")
            command = command.upper()
            server.commands.append(command)
            if command == "USER":
                user = argument
                send("+OK")
            elif command == "PASS":
                if (user, argument) != server.credentials:
                    send("-ERR invalid login")
                    return
                send("+OK")
            elif command == "UIDL":
                send("+OK")
                for number, (uidl, _) in enumerate(server.messages, 1):
                    send(f"{number} {uidl}")
                send(".")
            elif command == "LIST":
                send("+OK")
                for number, (_, raw) in enumerate(server.messages, 1):
                    send(f"{number} {len(raw)}")
                send(".")
            elif command == "RETR":
                send("+OK")
                for part in server.messages[int(argument) - 1][1].split(b"\r\n"):
                    self.wfile.write((b"." + part if part.startswith(b".") else part) + b"\r\n")
                send(".")
            elif command == "QUIT":
                send("+OK bye")
                return
            else:
                send("-ERR unsupported")


def pop3_server(cert, key, messages, credentials=("me", "secret")):
    server = _TLSServer(POP3Handler, cert, key)
    server.messages, server.credentials, server.commands = messages, credentials, []
    return server


class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        server = self.server
        send = lambda line: self.wfile.write(line.encode() + b"\r\n")  # noqa: E731
        send("220 localhost ESMTP")
        envelope = {"rcpt": []}
        while True:
            line = self.rfile.readline().decode("utf-8", "replace").rstrip("\r\n")
            if not line:
                return
            verb = line.split(" ")[0].upper()
            if verb in ("EHLO", "HELO"):
                self.wfile.write(b"250-localhost\r\n250-AUTH XOAUTH2 PLAIN LOGIN\r\n250 8BITMIME\r\n")
            elif verb == "AUTH":
                parts = line.split(" ")
                server.auth.append((parts[1], base64.b64decode(parts[2]).decode() if len(parts) > 2 else ""))
                send("235 ok" if server.accept_auth else "535 denied")
            elif verb == "MAIL":
                envelope["from"] = line
                send("250 ok")
            elif verb == "RCPT":
                envelope["rcpt"].append(line.split(":", 1)[1].strip().strip("<>"))
                send("250 ok")
            elif verb == "DATA":
                send("354 go")
                data = bytearray()
                while True:
                    chunk = self.rfile.readline()
                    if chunk in (b".\r\n", b""):
                        break
                    data += chunk
                server.deliveries.append((list(envelope["rcpt"]), bytes(data)))
                envelope = {"rcpt": []}
                send("250 queued")
            elif verb == "QUIT":
                send("221 bye")
                return
            else:
                send("250 ok")


def smtp_server(cert, key, accept_auth=True):
    server = _TLSServer(SMTPHandler, cert, key)
    server.auth, server.deliveries, server.accept_auth = [], [], accept_auth
    return server


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
