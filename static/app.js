"use strict";
const $ = id => document.getElementById(id);
const TOKEN_KEY = "portable-webmail-token";
const ROLE_LABELS = {inbox: "📥 受信トレイ", drafts: "📝 下書き", sent: "📤 送信済み", archive: "🗄 アーカイブ", all: "🗂 すべてのメール", junk: "⚠ 迷惑メール", trash: "🗑 ごみ箱"};
const MAX_UPLOAD = 30_000_000;
let token = "", accounts = [], accountId = null, folder = null, offset = 0;
let current = null, listGeneration = 0, detailGeneration = 0, general = {mark_read_on_open: true};
let selected = new Set(), moveTargetIds = [], editorState = null, presets = [];
const pageSize = 50;

function status(text, error = false) { $("status").textContent = text; $("status").classList.toggle("error", error); }
function fail(error) { status(error.message || String(error), true); }
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function setView(name) { document.body.classList.remove("view-list", "view-mail", "nav-open"); document.body.classList.add("view-" + name); }
function folderLabel(name, role) { return ROLE_LABELS[role] || "📁 " + name; }
function formatDate(ts) {
  if (!ts) return "";
  const date = new Date(ts * 1000), now = new Date();
  return date.toDateString() === now.toDateString() ? date.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"}) : date.toLocaleDateString();
}
function formatSize(bytes) { return bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(bytes / 1024)) + " KB"; }
function addressOf(text) { const match = (text || "").match(/<([^<>\s]+)>/); return (match ? match[1] : (text || "")).trim(); }
function splitAddresses(text) { return text.split(/[,;\n]/).map(x => x.trim()).filter(Boolean); }

async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {"Authorization": `Bearer ${token}`, "Content-Type": "application/json", ...options.headers}});
  if (options.raw) { if (!response.ok) throw new Error(`取得に失敗しました (${response.status})`); return response; }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : `入力または通信エラー (${response.status})`);
  return data;
}
const post = (path, body, headers = {}) => api(path, {method: "POST", body: JSON.stringify(body), headers});

/* ---------- folders and list ---------- */
function accountOf(id) { return accounts.find(a => a.id === id); }
function folderRole(id, name) { return accountOf(id)?.folders.find(f => f.folder === name)?.role || ""; }
async function loadAccounts() {
  accounts = await api("/api/accounts");
  $("accounts").replaceChildren();
  const choice = $("draft-account"), previous = choice.value; choice.replaceChildren();
  for (const account of accounts) {
    $("accounts").append(element("div", `${account.name}${account.enabled ? "" : "（無効）"}`, "account"));
    if (account.ready) { const opt = element("option", `${account.name} <${account.email}>`); opt.value = account.id; choice.append(opt); }
    for (const f of account.folders) {
      const button = element("button", undefined, "folder");
      button.title = f.folder;
      button.append(element("span", folderLabel(f.folder, f.role)), element("span", f.unread ? String(f.unread) : "", "count"));
      if (accountId === account.id && folder === f.folder) button.classList.add("active");
      button.onclick = () => { accountId = account.id; folder = f.folder; setView("list"); refresh().catch(fail); };
      $("accounts").append(button);
    }
  }
  if (previous) choice.value = previous;
  $("all").classList.toggle("active", !accountId);
  $("compose").disabled = !accounts.some(a => a.ready);
  const active = accountId && accountOf(accountId);
  $("title").textContent = active && folder ? folderLabel(folder, folderRole(accountId, folder)).replace(/^\S+\s/, "") : "Portable Webmail";
}
function updateBulk() {
  $("bulk").classList.toggle("hidden", !selected.size);
  $("bulk-count").textContent = `${selected.size}件選択`;
  for (const row of $("messages").children) if (row.dataset.id) row.classList.toggle("selected", selected.has(Number(row.dataset.id)));
}
function renderRow(row) {
  const item = element("div", undefined, `mail ${row.is_seen ? "" : "unread"}`); item.dataset.id = row.id;
  if (current && current.id === row.id) item.classList.add("current");
  const pick = element("label", undefined, "pick"), box = document.createElement("input");
  box.type = "checkbox"; box.checked = selected.has(row.id); box.setAttribute("aria-label", "選択");
  box.onchange = () => { box.checked ? selected.add(row.id) : selected.delete(row.id); updateBulk(); };
  pick.append(box);
  const star = element("button", row.is_flagged ? "★" : "☆", `star ${row.is_flagged ? "on" : ""}`);
  star.setAttribute("aria-label", "スター"); star.type = "button";
  star.onclick = () => changeFlags([row.id], {flagged: !row.is_flagged});
  const open = element("button", undefined, "open"); open.type = "button";
  const role = folderRole(row.account_id, row.folder);
  let who = row.sender;
  if (role === "sent" || role === "drafts") {
    let list = []; try { list = JSON.parse(row.recipients); } catch (e) { /* keep empty */ }
    who = "宛先: " + (list.map(r => r.name || r.address).join(", ") || "（未設定）");
  }
  const top = element("span", undefined, "top");
  top.append(element("span", who), element("span", `${row.has_attachments ? "📎 " : ""}${row.is_answered ? "↩ " : ""}${formatDate(row.date_ts)}`));
  open.append(top, element("strong", row.subject || "（件名なし）"), element("span", row.snippet));
  if (!accountId) open.append(element("span", `${accountOf(row.account_id)?.name || row.account_id} / ${folderLabel(row.folder, role)}`));
  open.onclick = () => showEmail(row.id).catch(fail);
  item.append(pick, star, open);
  return item;
}
async function loadMessages(append = false) {
  const generation = ++listGeneration;
  if (!append) offset = 0;
  const params = new URLSearchParams({query: $("query").value, limit: pageSize, offset});
  if (accountId) params.set("account_id", accountId);
  if (folder) params.set("folder", folder);
  for (const name of ["unread", "flagged", "attachments"]) if ($("filter-" + name).checked) params.set(name, "true");
  const rows = await api(`/api/emails?${params}`);
  if (generation !== listGeneration) return;
  if (!append) { $("messages").replaceChildren(); selected = new Set([...selected].filter(id => rows.some(r => r.id === id))); }
  if (!rows.length && !append) $("messages").append(element("div", "メールがありません。", "empty"));
  for (const row of rows) $("messages").append(renderRow(row));
  offset += rows.length;
  $("more").classList.toggle("hidden", rows.length < pageSize);
  $("select-all").checked = false;
  updateBulk();
}
async function refresh() { await loadAccounts(); await loadMessages(); }

/* ---------- actions on mail ---------- */
async function afterChange(ids, removed) {
  for (const id of ids) selected.delete(id);
  if (removed && current && ids.includes(current.id)) {
    current = null; $("preview").replaceChildren(element("div", "メールを選択してください。", "empty")); setView("list");
  }
  await refresh();
}
async function changeFlags(ids, change) {
  try { await post("/api/emails/flags", {ids, ...change}); await refresh(); if (current && ids.includes(current.id)) await showEmail(current.id, false); }
  catch (e) { fail(e); }
}
async function archiveMails(ids) {
  try { await post("/api/emails/archive", {ids}); status(`${ids.length}件をアーカイブしました。`); await afterChange(ids, true); } catch (e) { fail(e); }
}
async function deleteMails(ids, permanent = false) {
  if (permanent && !window.confirm(`${ids.length}件を完全に削除します。元に戻せません。よろしいですか？`)) return;
  try {
    const result = await post("/api/emails/delete", {ids, permanent});
    status(result.deleted ? `${result.deleted}件を完全に削除しました。` : `${result.trashed}件をごみ箱へ移動しました。`);
    await afterChange(ids, true);
  } catch (e) { fail(e); }
}
function inTrash(mail) { return folderRole(mail.account_id, mail.folder) === "trash"; }
function openMove(ids, account) {
  moveTargetIds = ids; $("move-list").replaceChildren();
  const boxes = accountOf(account)?.mailboxes || [];
  if (!boxes.length) $("move-list").append(element("p", "移動先フォルダがありません。同期後にもう一度お試しください。"));
  for (const box of boxes) {
    const button = element("button", folderLabel(box.name, box.role)); button.title = box.name; button.type = "button";
    button.onclick = async () => {
      $("move-dialog").close();
      try { await post("/api/emails/move", {ids: moveTargetIds, folder: box.name}); status(`${moveTargetIds.length}件を移動しました。`); await afterChange(moveTargetIds, true); } catch (e) { fail(e); }
    };
    $("move-list").append(button);
  }
  $("move-dialog").showModal();
}
function selectedRows() { return [...selected]; }
function selectedAccount() {
  // Moving needs one account's folder list; the unified view may mix accounts.
  if (accountId) return accountId;
  return current && selected.has(current.id) ? current.account_id : null;
}
$("bulk").onclick = event => {
  const action = event.target.dataset.bulk, ids = selectedRows();
  if (!action || !ids.length) return;
  if (action === "read") changeFlags(ids, {seen: true});
  else if (action === "unread") changeFlags(ids, {seen: false});
  else if (action === "star") changeFlags(ids, {flagged: true});
  else if (action === "archive") archiveMails(ids);
  else if (action === "delete") deleteMails(ids, Boolean(accountId && folder && folderRole(accountId, folder) === "trash"));
  else if (action === "move") {
    const account = selectedAccount();
    if (!account) return status("移動するには、左のフォルダ一覧からアカウントのフォルダを開いて選択してください。", true);
    openMove(ids, account);
  }
};
$("select-all").onchange = () => {
  for (const row of $("messages").children) {
    if (!row.dataset.id) continue;
    const id = Number(row.dataset.id), box = row.querySelector("input");
    box.checked = $("select-all").checked; box.checked ? selected.add(id) : selected.delete(id);
  }
  updateBulk();
};

/* ---------- reading ---------- */
function safeHTML(html, images = {}) {
  // Template contents are inert; remove navigation and executable containers
  // before placing anything into the sandboxed iframe.
  const template = document.createElement("template");
  template.innerHTML = html;
  template.content.querySelectorAll("script,meta,base,link,iframe,frame,frameset,object,embed,form,input,button,textarea,select,video,audio,source,svg,math").forEach(node => node.remove());
  for (const node of template.content.querySelectorAll("*")) {
    for (const attribute of Array.from(node.attributes)) {
      const name = attribute.name.toLowerCase();
      let value = attribute.value;
      if (name === "src" && node.tagName === "IMG" && /^cid:/i.test(value)) {
        // Server-provided data: URI for an image attached to this very message.
        const inline = images[value.slice(4)];
        if (inline) { node.setAttribute("src", inline); value = inline; }
      }
      if (!["style", "class", "id", "title", "alt", "width", "height", "colspan", "rowspan", "dir", "lang", "src"].includes(name) ||
          (name === "src" && !(node.tagName === "IMG" && /^data:image\/(png|jpeg|gif|webp);base64,/i.test(value)))) node.removeAttribute(attribute.name);
    }
  }
  return template.innerHTML;
}
function showBody(mail, htmlMode = false, images = {}) {
  const target = $("mail-body"); target.replaceChildren();
  if (htmlMode && mail.body_html) {
    const frame = document.createElement("iframe");
    frame.title = "隔離されたHTMLメール";
    frame.setAttribute("sandbox", "");
    frame.referrerPolicy = "no-referrer";
    // No innerHTML interpolation into the parent, no scripts, no same-origin,
    // no network images/styles/fonts/forms, no popup/top-navigation privileges.
    // The CSP is first and cannot be relaxed by later email <meta> tags.
    frame.srcdoc = '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><style>body{overflow-wrap:anywhere;font:14px/1.6 sans-serif}img{max-width:100%;height:auto}table{max-width:100%}</style></head><body>' + safeHTML(mail.body_html, images) + '</body></html>';
    target.append(frame);
  } else target.append(element("pre", mail.body_text || "（本文なし）"));
}
async function downloadAttachment(mail, item) {
  try {
    const response = await api(`/api/emails/${mail.id}/attachments/${item.index}`, {raw: true});
    const url = URL.createObjectURL(new Blob([await response.blob()], {type: "application/octet-stream"}));
    const link = document.createElement("a"); link.href = url; link.download = item.filename;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (e) { fail(e); }
}
function recipientLines(mail) {
  return mail.recipients.map(r => `${r.type === "to" ? "宛先" : r.type.toUpperCase()}: ${r.name ? r.name + " " : ""}<${r.address}>`).join("\n");
}
async function showEmail(id, markRead = true) {
  const generation = ++detailGeneration;
  const mail = await api(`/api/emails/${id}`);
  if (generation !== detailGeneration) return;
  current = mail; setView("mail");
  for (const row of $("messages").children) row.classList.toggle("current", Number(row.dataset.id) === id);
  const pane = $("preview"); pane.replaceChildren(); pane.scrollTop = 0;
  pane.append(element("h2", mail.subject || "（件名なし）"));
  const role = folderRole(mail.account_id, mail.folder) || mail.folder_role;
  const when = mail.date_ts ? new Date(mail.date_ts * 1000).toLocaleString() : "";
  pane.append(element("div", `差出人: ${mail.sender}\n${recipientLines(mail)}\n${when}\n${accountOf(mail.account_id)?.name || mail.account_id} / ${folderLabel(mail.folder, role)}`, "meta"));
  const ready = Boolean(accountOf(mail.account_id)?.ready);
  const actions = element("div", undefined, "actions");
  const add = (label, handler, className) => { const b = element("button", label, className); b.type = "button"; b.onclick = handler; actions.append(b); return b; };
  if (mail.is_draft) {
    add("✎ 編集", () => openEditor("edit", mail)).disabled = !ready;
    const send = add(mail.send_state ? `送信処理済み: ${mail.send_state}` : "確認して送信", async () => {
      if (!window.confirm(`この下書きを送信しますか？\n差出人: ${mail.sender}\n${recipientLines(mail)}\n件名: ${mail.subject}${mail.attachments.length ? "\n添付: " + mail.attachments.map(a => a.filename).join(", ") : ""}`)) return;
      send.disabled = true;
      try { reportSend(await post(`/api/drafts/${mail.id}/send`, {}, {"X-Confirm-Send": "human-reviewed"})); await afterChange([mail.id], true); }
      catch (e) { fail(e); await showEmail(mail.id, false).catch(() => {}); }
    }, "primary");
    send.disabled = Boolean(mail.send_state) || !ready || !mail.recipients.length;
  } else {
    add("↩ 返信", () => openEditor("reply", mail)).disabled = !ready;
    add("↩↩ 全員に返信", () => openEditor("replyAll", mail)).disabled = !ready;
    add("→ 転送", () => openEditor("forward", mail)).disabled = !ready;
  }
  add(mail.is_flagged ? "★ スター解除" : "☆ スター", () => changeFlags([mail.id], {flagged: !mail.is_flagged})).disabled = !ready;
  add(mail.is_seen ? "未読にする" : "既読にする", () => changeFlags([mail.id], {seen: !mail.is_seen})).disabled = !ready;
  if (!["archive", "all", "drafts", "sent", "trash"].includes(role)) add("🗄 アーカイブ", () => archiveMails([mail.id])).disabled = !ready;
  add("📁 移動", () => openMove([mail.id], mail.account_id)).disabled = !ready;
  add(inTrash(mail) ? "完全に削除" : "🗑 削除", () => deleteMails([mail.id], inTrash(mail)), "danger").disabled = !ready;
  add("スレッド", async () => {
    try {
      const rows = await api(`/api/emails/${mail.id}/thread`);
      const area = $("thread-list"); area.replaceChildren();
      for (const row of rows) { const b = element("button", `${formatDate(row.date_ts)}  ${row.sender}  ${row.subject}`); b.type = "button"; b.disabled = row.id === mail.id; b.onclick = () => showEmail(row.id).catch(fail); area.append(b); }
    } catch (e) { fail(e); }
  });
  let images = null;
  if (mail.body_html) {
    let mode = false; const toggle = add("HTML表示（外部画像は遮断）", async () => {
      mode = !mode; toggle.textContent = mode ? "テキスト表示" : "HTML表示（外部画像は遮断）";
      if (mode && images === null) {
        images = {};
        if (ready && mail.attachments.some(a => a.cid)) { try { images = await api(`/api/emails/${mail.id}/inline`); } catch (e) { /* show without inline images */ } }
      }
      showBody(mail, mode, images || {});
    });
  }
  pane.append(actions);
  const files = mail.attachments.filter(a => !a.inline);
  if (files.length) {
    const area = element("div", undefined, "attachments");
    for (const item of files) { const b = element("button", `📎 ${item.filename}（${formatSize(item.size)}）`); b.type = "button"; b.disabled = !ready; b.onclick = () => downloadAttachment(mail, item); area.append(b); }
    pane.append(area);
  }
  const threads = element("div"); threads.id = "thread-list"; pane.append(threads);
  const body = element("div"); body.id = "mail-body"; pane.append(body); showBody(mail);
  if (markRead && general.mark_read_on_open && !mail.is_seen && ready && !mail.is_draft) {
    post("/api/emails/flags", {ids: [mail.id], seen: true}).then(() => { mail.is_seen = 1; return refresh(); }).catch(() => {});
  }
}
function reportSend(result) {
  const warnings = (result.warnings || []).join(" ");
  if (result.state === "accepted") status("送信しました（SMTPサーバーが受け付けました）。" + warnings, Boolean(warnings));
  else status(`一部の宛先が拒否されました: ${result.refused.join(", ")}。自動再送はしません。${warnings}`, true);
}

/* ---------- composing ---------- */
function renderEditorAttachments() {
  const area = $("draft-attachments"); area.replaceChildren();
  for (const item of editorState.source) {
    const label = element("label"); const box = document.createElement("input"); box.type = "checkbox"; box.checked = item.keep;
    box.onchange = () => { item.keep = box.checked; };
    label.append(box, document.createTextNode(` 📎 ${item.filename}（${formatSize(item.size)}）`)); area.append(label);
  }
  editorState.files.forEach((file, index) => {
    const b = element("button", `📎 ${file.name}（${formatSize(file.size)}） ✕`); b.type = "button"; b.title = "添付を取り消す";
    b.onclick = () => { editorState.files.splice(index, 1); renderEditorAttachments(); };
    area.append(b);
  });
}
function quote(mail) {
  const when = mail.date_ts ? new Date(mail.date_ts * 1000).toLocaleString() : "";
  return `\n\n${when} ${mail.sender}:\n${mail.body_text.slice(0, 50000).split("\n").map(x => "> " + x).join("\n")}`;
}
function signatureOf(id) { const text = accountOf(id)?.signature; return text ? `\n\n-- \n${text}` : ""; }
function openEditor(mode = "new", mail = null) {
  editorState = {mode, replyId: null, replaceId: null, sourceId: null, source: [], files: []};
  const account = mail ? mail.account_id : (accountId && accountOf(accountId)?.ready ? accountId : accounts.find(a => a.ready)?.id || "");
  $("draft-account").value = account; $("draft-account").disabled = Boolean(mail);
  const own = (accountOf(account)?.email || "").toLowerCase();
  let to = [], cc = [], bcc = [], subject = "", body = signatureOf(account);
  const others = type => mail.recipients.filter(r => r.type === type).map(r => r.address);
  const prefixed = (prefix, pattern) => pattern.test(mail.subject) ? mail.subject : `${prefix}: ${mail.subject}`;
  if (mode === "reply" || mode === "replyAll") {
    // A reply address is only a suggestion and remains visibly editable.
    editorState.replyId = mail.id;
    to = [addressOf(mail.reply_to || mail.sender)];
    if (mode === "replyAll") {
      const seen = new Set([own, ...to.map(a => a.toLowerCase())]);
      for (const address of [...others("to"), ...others("cc")]) if (!seen.has(address.toLowerCase())) { seen.add(address.toLowerCase()); cc.push(address); }
    }
    subject = prefixed("Re", /^re:/i); body = signatureOf(account) + quote(mail);
  } else if (mode === "forward") {
    subject = prefixed("Fwd", /^(fwd?|fw):/i);
    body = `${signatureOf(account)}\n\n---------- 転送メッセージ ----------\n差出人: ${mail.sender}\n件名: ${mail.subject}\n${recipientLines(mail)}\n\n${mail.body_text.slice(0, 200000)}`;
    editorState.sourceId = mail.id; editorState.source = mail.attachments.filter(a => !a.inline).map(a => ({...a, keep: true}));
  } else if (mode === "edit") {
    editorState.replaceId = mail.id; editorState.sourceId = mail.id;
    to = others("to"); cc = others("cc"); bcc = others("bcc"); subject = mail.subject; body = mail.body_text;
    editorState.source = mail.attachments.map(a => ({...a, keep: true}));
  }
  $("editor-title").textContent = {new: "メールを作成", reply: "返信", replyAll: "全員に返信", forward: "転送", edit: "下書きを編集"}[mode];
  $("draft-to").value = to.join(", "); $("draft-cc").value = cc.join(", "); $("draft-bcc").value = bcc.join(", ");
  $("draft-subject").value = subject; $("draft-body").value = body; $("draft-files").value = "";
  $("draft-error").textContent = ""; renderEditorAttachments(); $("editor").showModal();
  const focus = mode === "new" || mode === "forward" ? $("draft-to") : $("draft-body");
  focus.focus(); if (focus === $("draft-body")) focus.setSelectionRange(0, 0);
}
function readFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve({filename: file.name, content_type: file.type || "application/octet-stream", data: String(reader.result).split(",")[1] || ""});
    reader.onerror = () => reject(new Error(`${file.name} を読み込めません。`));
    reader.readAsDataURL(file);
  });
}
async function editorPayload() {
  const keep = editorState.source.filter(a => a.keep).map(a => a.index);
  if (editorState.files.reduce((sum, f) => sum + f.size, 0) > MAX_UPLOAD) throw new Error("添付ファイルの合計は30MBまでです。");
  return {account_id: $("draft-account").value, to: splitAddresses($("draft-to").value), cc: splitAddresses($("draft-cc").value), bcc: splitAddresses($("draft-bcc").value),
    subject: $("draft-subject").value, body: $("draft-body").value, reply_to_email_id: editorState.replyId, replace_email_id: editorState.replaceId,
    source_attachments: keep.length ? {email_id: editorState.sourceId, indexes: keep} : null,
    attachments: await Promise.all(editorState.files.map(readFile))};
}
async function submitEditor(send) {
  $("draft-error").textContent = "";
  for (const id of ["save-draft", "send-draft"]) $(id).disabled = true;
  try {
    const payload = await editorPayload();
    if (send) {
      const all = [...payload.to, ...payload.cc, ...payload.bcc];
      if (!all.length) throw new Error("宛先を入力してください。");
      const files = [...editorState.source.filter(a => a.keep).map(a => a.filename), ...editorState.files.map(f => f.name)];
      if (!window.confirm(`送信しますか？\n宛先: ${payload.to.join(", ") || "（なし）"}${payload.cc.length ? "\nCc: " + payload.cc.join(", ") : ""}${payload.bcc.length ? "\nBcc: " + payload.bcc.join(", ") : ""}\n件名: ${payload.subject || "（件名なし）"}${files.length ? "\n添付: " + files.join(", ") : ""}`)) return;
      reportSend(await post("/api/send", payload, {"X-Confirm-Send": "human-reviewed"}));
    } else {
      const result = await post("/api/drafts", payload);
      status("下書きを保存しました。" + (result.warnings || []).join(" "), Boolean(result.warnings));
    }
    const replaced = editorState.replaceId;
    $("editor").close();
    await afterChange(replaced ? [replaced] : [], Boolean(replaced));
  } catch (e) { $("draft-error").textContent = e.message; }
  finally { for (const id of ["save-draft", "send-draft"]) $(id).disabled = false; }
}
$("draft-files").onchange = () => { editorState.files.push(...$("draft-files").files); $("draft-files").value = ""; renderEditorAttachments(); };
$("draft-form").onsubmit = event => { event.preventDefault(); submitEditor(true); };
$("save-draft").onclick = () => submitEditor(false);
$("cancel-draft").onclick = () => $("editor").close();
$("compose").onclick = () => openEditor();

/* ---------- session ---------- */
$("login").addEventListener("cancel", event => event.preventDefault());
async function connect(value, remember) {
  token = value;
  await refresh();
  try { remember ? localStorage.setItem(TOKEN_KEY, value) : localStorage.removeItem(TOKEN_KEY); } catch (e) { /* storage unavailable */ }
  if ($("login").open) $("login").close();
  status("接続しました。件数はこの端末に取り込み済みのメールが基準です。");
  await offerUnlock();
}
$("login-form").onsubmit = async event => {
  event.preventDefault();
  try { await connect($("token").value.trim(), $("remember-token").checked); $("token").value = ""; }
  catch (e) { token = ""; $("login-error").textContent = e.message; }
};
$("logout").onclick = () => { try { localStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ } location.reload(); };
$("search-form").onsubmit = event => { event.preventDefault(); setView("list"); loadMessages().catch(fail); };
for (const name of ["unread", "flagged", "attachments"]) $("filter-" + name).onchange = () => loadMessages().catch(fail);
$("all").onclick = () => { accountId = null; folder = null; setView("list"); refresh().catch(fail); };
$("more").onclick = () => loadMessages(true).catch(fail);
$("menu").onclick = () => document.body.classList.toggle("nav-open");
$("scrim").onclick = () => document.body.classList.remove("nav-open");
$("back").onclick = () => setView("list");
$("cancel-move").onclick = () => $("move-dialog").close();
$("sync").onclick = async () => { try { await post("/api/sync", {}); status("同期を要求しました。数秒後に一覧を更新します。"); setTimeout(() => refresh().catch(fail), 4000); } catch (e) { fail(e); } };
let syncErrorShown = false;
setInterval(async () => {
  if (!token || document.hidden || [...document.querySelectorAll("dialog")].some(d => d.open)) return;
  try {
    await loadAccounts();
    // Reloading resets to page 1 and the selection; keep the list while the user works in it.
    if (offset <= pageSize && !selected.size) await loadMessages();
    const states = await api("/api/sync");
    const errors = Object.entries(states).filter(([, value]) => !value.ok);
    if (errors.length) {
      status(`同期エラー: ${errors.map(([id, value]) => `${id}: ${value.error}`).join(" / ")}`, true);
      syncErrorShown = true;
    } else if (syncErrorShown) { status("同期は正常に戻りました。"); syncErrorShown = false; }
  } catch (e) { fail(e); }
}, 15000);
(async () => {
  let saved = ""; try { saved = localStorage.getItem(TOKEN_KEY) || ""; } catch (e) { /* ignore */ }
  if (saved) { try { await connect(saved, true); return; } catch (e) { token = ""; } }
  $("login").showModal();
})();

/* ---------- settings ---------- */
let accountState = null, oauthPoll = null;
function clearAccountSecrets() {
  for (const id of ["master-password", "master-confirm", "imap-password", "smtp-password", "oauth-client-secret"]) $(id).value = "";
}
function presetOf(id) { return presets.find(p => p.id === id) || presets.find(p => p.id === "generic"); }
function updateAccountForm() {
  const oauth = $("account-auth").value === "oauth2", pop = $("account-protocol").value === "pop3";
  $("oauth-fields").classList.toggle("hidden", !oauth);
  for (const node of document.querySelectorAll(".password-field")) node.classList.toggle("hidden", oauth);
  for (const node of document.querySelectorAll(".imap-only")) node.classList.toggle("hidden", pop);
  $("folders-label").classList.toggle("hidden", pop || $("account-allfolders").checked);
  $("account-auth").querySelector("[value=oauth2]").disabled = pop;
  $("oauth-tenant").closest("label").classList.toggle("hidden", $("oauth-provider").value !== "microsoft");
  const account = accountState?.accounts.find(a => a.id === $("account-id").value);
  const saved = account?.oauth && account.auth === "oauth2";
  $("oauth-status").textContent = !oauth ? "" : saved ? (account.oauth.signed_in ? "✅ サインイン済みです。" : "未サインインです。「サインイン」を押してください。") : "先に「暗号化して保存」を押してから、サインインしてください。";
  $("oauth-signin").disabled = !saved;
  $("delete-account").disabled = !account; $("test-account").disabled = !account;
}
function applyPreset() {
  const preset = presetOf($("account-provider").value);
  $("provider-note").textContent = preset.note;
  $("account-protocol").value = preset.protocol;
  for (const kind of ["imap", "smtp"]) {
    $(kind + "-host").value = preset[kind].host; $(kind + "-port").value = preset[kind].port; $(kind + "-security").value = preset[kind].security;
    if (!$(kind + "-username").value) $(kind + "-username").value = $("account-email").value;
  }
  $("account-savesent").checked = preset.save_sent;
  $("account-allfolders").checked = preset.folders.includes("*");
  if (preset.oauth) { $("oauth-provider").value = preset.oauth; $("oauth-tenant").value = preset.tenant; }
  // Microsoft no longer accepts passwords; everything else starts with an (app) password.
  $("account-auth").value = preset.oauth === "microsoft" ? "oauth2" : "password";
  updateAccountForm();
}
function selectAccount(id = "") {
  const account = accountState.accounts.find(a => a.id === id);
  $("account-choice").value = account ? id : "";
  $("account-provider").value = presetOf(account?.provider || "generic").id;
  $("provider-note").textContent = presetOf($("account-provider").value).note;
  $("account-id").value = account?.id || ""; $("account-id").readOnly = Boolean(account);
  $("account-name").value = account?.name || ""; $("account-email").value = account?.email || "";
  $("account-display").value = account?.display_name || ""; $("account-signature").value = account?.signature || "";
  $("account-enabled").checked = account ? account.enabled : true;
  $("account-protocol").value = account?.protocol || "imap"; $("account-auth").value = account?.auth || "password";
  $("oauth-provider").value = account?.oauth?.provider || "google"; $("oauth-client-id").value = account?.oauth?.client_id || "";
  $("oauth-tenant").value = account?.oauth?.tenant || "common";
  $("oauth-client-secret").placeholder = account?.oauth?.has_client_secret ? "登録済み（変更しない場合は空欄）" : "";
  const folders = account?.folders || ["*"];
  $("account-allfolders").checked = folders.includes("*");
  $("account-folders").value = folders.filter(f => f !== "*").join("\n") || "INBOX";
  $("account-drafts").value = account?.drafts_folder || ""; $("account-sent").value = account?.sent_folder || "";
  $("account-trash").value = account?.trash_folder || ""; $("account-archive").value = account?.archive_folder || "";
  $("account-savesent").checked = account ? account.save_sent : true;
  for (const kind of ["imap", "smtp"]) {
    const endpoint = account?.[kind];
    $(kind + "-host").value = endpoint?.host || ""; $(kind + "-port").value = endpoint?.port || (kind === "imap" ? 993 : 465);
    $(kind + "-security").value = endpoint?.security || "tls"; $(kind + "-username").value = endpoint?.username || "";
    $(kind + "-password").value = "";
    $(kind + "-password").placeholder = endpoint?.has_password ? "登録済み（変更しない場合は空欄）" : "パスワードを入力";
  }
  $("oauth-link").classList.add("hidden"); $("test-result").textContent = "";
  updateAccountForm();
}
function renderAccountSettings(state, selection = "") {
  accountState = state; general = state;
  $("vault-status").textContent = state.encrypted ? (state.locked ? "🔒 ロック中です。解除するとメールの同期を開始します。" : "🔓 ロック解除中。サーバーを停止すると再びロックされます。") : "初回設定：マスターパスワードを決めてください。メールのパスワードを暗号化して保存します。";
  $("unlock-form").classList.toggle("hidden", !state.locked);
  $("master-confirm-label").classList.toggle("hidden", state.encrypted); $("initial-mcp-label").classList.toggle("hidden", state.encrypted);
  $("master-confirm").required = !state.encrypted; $("master-password").minLength = state.encrypted ? 1 : 12;
  $("unlock-button").textContent = state.encrypted ? "ロックを解除" : "この内容で開始";
  $("vault-help").textContent = state.encrypted ? "起動後に一度、マスターパスワードを入力してください。" : "12文字以上の、長く推測されにくいパスワードを設定してください。";
  $("account-fields").disabled = state.locked; $("general-fields").disabled = state.locked;
  $("general-mcp").value = state.mcp_permissions; $("general-markread").checked = state.mark_read_on_open;
  $("general-hosts").value = state.allowed_hosts.join("\n");
  $("account-choice").replaceChildren();
  const fresh = element("option", "＋ 新しく登録する"); fresh.value = ""; $("account-choice").append(fresh);
  for (const account of state.accounts) {
    const option = element("option", `${account.name} (${account.email})${account.enabled ? "" : "・無効"}`);
    option.value = account.id; $("account-choice").append(option);
  }
  selectAccount(selection);
}
async function openAccountSettings(initialState = null) {
  clearAccountSecrets(); $("settings-error").textContent = "";
  if (!presets.length) {
    presets = await api("/api/providers");
    for (const preset of presets) { const option = element("option", preset.label); option.value = preset.id; $("account-provider").append(option); }
  }
  renderAccountSettings(initialState || await api("/api/settings"));
  if (!$("settings-dialog").open) $("settings-dialog").showModal();
}
async function offerUnlock() {
  try {
    const state = await api("/api/settings"); general = state;
    if (state.locked || !state.accounts.some(a => a.enabled)) await openAccountSettings(state);
  } catch (e) { fail(e); }
}
async function settingsAction(button, work) {
  button.disabled = true; $("settings-error").textContent = "";
  try { await work(); } catch (e) { $("settings-error").textContent = e.message; $("settings-error").scrollIntoView({block: "center"}); }
  finally { button.disabled = false; }
}
$("account-settings").onclick = () => openAccountSettings().catch(fail);
$("account-choice").onchange = () => selectAccount($("account-choice").value);
$("account-provider").onchange = applyPreset;
for (const id of ["account-auth", "account-protocol", "account-allfolders", "oauth-provider"]) $(id).addEventListener("change", updateAccountForm);
$("close-settings").onclick = () => $("settings-dialog").close();
$("settings-dialog").addEventListener("close", () => { clearAccountSecrets(); clearInterval(oauthPoll); refresh().catch(fail); });
$("unlock-form").onsubmit = event => {
  event.preventDefault();
  settingsAction($("unlock-button"), async () => {
    try {
      const first = !accountState.encrypted;
      const result = await post("/api/settings/unlock", {master_password: $("master-password").value, confirmation: first ? $("master-confirm").value : null, mcp_permissions: first ? $("initial-mcp").value : null});
      renderAccountSettings(result); status("ロックを解除しました。"); await refresh();
    } finally { $("master-password").value = ""; $("master-confirm").value = ""; }
  });
};
$("general-form").onsubmit = event => {
  event.preventDefault();
  settingsAction($("save-general"), async () => {
    const result = await api("/api/settings/general", {method: "PUT", body: JSON.stringify({mcp_permissions: $("general-mcp").value, mark_read_on_open: $("general-markread").checked, allowed_hosts: $("general-hosts").value.split("\n").map(v => v.trim()).filter(Boolean)})});
    renderAccountSettings(result, $("account-choice").value); $("vault-status").textContent = "全般設定を保存しました。";
  });
};
$("account-form").onsubmit = event => {
  event.preventDefault();
  settingsAction($("save-account"), async () => {
    const pop = $("account-protocol").value === "pop3", oauth = $("account-auth").value === "oauth2" && !pop;
    const text = id => $(id).value.trim() || null;
    const folders = pop ? ["INBOX"] : $("account-allfolders").checked ? ["*"] : $("account-folders").value.split("\n").map(v => v.trim()).filter(Boolean);
    const input = {id: $("account-id").value.trim(), name: $("account-name").value.trim(), email: $("account-email").value.trim(), enabled: $("account-enabled").checked,
      protocol: $("account-protocol").value, provider: $("account-provider").value, auth: oauth ? "oauth2" : "password",
      oauth: oauth ? {provider: $("oauth-provider").value, client_id: $("oauth-client-id").value.trim(), tenant: $("oauth-tenant").value.trim() || "common", client_secret: $("oauth-client-secret").value} : null,
      folders, drafts_folder: pop ? null : text("account-drafts"), sent_folder: pop ? null : text("account-sent"), trash_folder: pop ? null : text("account-trash"), archive_folder: pop ? null : text("account-archive"),
      save_sent: $("account-savesent").checked, display_name: $("account-display").value.trim(), signature: $("account-signature").value};
    for (const kind of ["imap", "smtp"]) input[kind] = {host: $(kind + "-host").value.trim(), port: Number($(kind + "-port").value), username: $(kind + "-username").value.trim(), security: $(kind + "-security").value, password: oauth ? "" : $(kind + "-password").value};
    const result = await api(`/api/settings/accounts/${encodeURIComponent(input.id)}`, {method: "PUT", body: JSON.stringify(input)});
    clearAccountSecrets(); renderAccountSettings(result, input.id);
    $("vault-status").textContent = oauth && !result.accounts.find(a => a.id === input.id).oauth.signed_in ? "保存しました。続けて「サインイン」を押してください。" : "保存しました。同期を開始します。";
  });
};
$("delete-account").onclick = () => {
  const id = $("account-choice").value;
  if (!id || !window.confirm(`アカウント「${id}」の設定と、この端末に取り込んだメールを削除します。サーバー上のメールは削除されません。よろしいですか？`)) return;
  settingsAction($("delete-account"), async () => { renderAccountSettings(await api(`/api/settings/accounts/${encodeURIComponent(id)}`, {method: "DELETE"})); $("vault-status").textContent = "アカウントを削除しました。"; });
};
$("test-account").onclick = () => settingsAction($("test-account"), async () => {
  $("test-result").textContent = "接続テスト中…（保存済みの設定で確認します）";
  try {
    const result = await post(`/api/settings/accounts/${encodeURIComponent($("account-choice").value)}/test`, {});
    const line = (label, value) => `${label}: ${value.ok ? "✅ 接続できました" : "❌ " + value.error}`;
    $("test-result").textContent = `${line("受信", result.incoming)} ／ ${line("送信(SMTP)", result.smtp)}`;
  } catch (e) { $("test-result").textContent = ""; throw e; }
});
$("oauth-signin").onclick = () => settingsAction($("oauth-signin"), async () => {
  const id = $("account-choice").value;
  const result = await post("/api/oauth/start", {account_id: id});
  const link = $("oauth-link"); link.href = result.url; link.classList.remove("hidden");
  $("oauth-status").textContent = "「サインインページを開く」から認証してください。完了すると自動で反映されます。";
  clearInterval(oauthPoll); let tries = 0;
  oauthPoll = setInterval(async () => {
    if (++tries > 100 || !$("settings-dialog").open) return clearInterval(oauthPoll);
    try {
      const state = await api("/api/settings");
      if (state.accounts.find(a => a.id === id)?.oauth?.signed_in) { clearInterval(oauthPoll); renderAccountSettings(state, id); $("vault-status").textContent = "サインインが完了しました。同期を開始します。"; }
    } catch (e) { /* keep polling */ }
  }, 3000);
});
