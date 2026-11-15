"use strict";
const $ = id => document.getElementById(id);
let token = "", accounts = [], accountId = null, folder = null, offset = 0;
let current = null, replyId = null, listGeneration = 0, detailGeneration = 0;
const pageSize = 50;
function status(text, error = false) { $("status").textContent = text; $("status").classList.toggle("error", error); }
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {"Authorization": `Bearer ${token}`, "Content-Type": "application/json", ...options.headers}});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : `入力または通信エラー (${response.status})`);
  return data;
}
async function loadAccounts() {
  accounts = await api("/api/accounts");
  $("accounts").replaceChildren(); $("draft-account").replaceChildren();
  for (const account of accounts) {
    $("accounts").append(element("div", `${account.name} (${account.unread}/${account.total})${account.enabled ? "" : "・無効"}`, "account"));
    if (account.enabled) {
      const opt = element("option", account.email); opt.value = account.id; $("draft-account").append(opt);
    }
    for (const f of account.folders) {
      const button = element("button", `${f.folder}  ${f.unread}/${f.total}`, "folder");
      if (accountId === account.id && folder === f.folder) button.classList.add("active");
      button.onclick = () => { accountId = account.id; folder = f.folder; refresh().catch(fail); };
      $("accounts").append(button);
    }
  }
  $("compose").disabled = !accounts.some(a => a.enabled);
}
async function loadMessages(append = false) {
  const generation = ++listGeneration;
  if (!append) offset = 0;
  const params = new URLSearchParams({query: $("query").value, limit: pageSize, offset});
  if (accountId) params.set("account_id", accountId);
  if (folder) params.set("folder", folder);
  const rows = await api(`/api/emails?${params}`);
  if (generation !== listGeneration) return;
  if (!append) $("messages").replaceChildren();
  if (!rows.length && !append) $("messages").append(element("div", "メールがありません。初回はアカウント設定と同期を確認してください。", "empty"));
  for (const row of rows) {
    const button = element("button", undefined, `mail ${row.is_seen ? "" : "unread"}`);
    button.append(element("strong", row.subject || "（件名なし）"), element("span", row.sender), element("span", `${row.account_id} / ${row.folder} · ${new Date(row.date_ts * 1000).toLocaleString()}`), element("span", row.snippet));
    button.onclick = () => showEmail(row.id).catch(fail);
    $("messages").append(button);
  }
  offset += rows.length;
  $("more").classList.toggle("hidden", rows.length < pageSize);
}
function fail(error) { status(error.message || String(error), true); }
async function refresh() { await loadAccounts(); await loadMessages(); }
function safeHTML(html) {
  // Template contents are inert; remove navigation and executable containers
  // before placing anything into the sandboxed iframe.
  const template = document.createElement("template");
  template.innerHTML = html;
  template.content.querySelectorAll("script,meta,base,link,iframe,frame,frameset,object,embed,form,input,button,textarea,select,video,audio,source,svg,math").forEach(node => node.remove());
  for (const node of template.content.querySelectorAll("*")) {
    for (const attribute of Array.from(node.attributes)) {
      const name = attribute.name.toLowerCase();
      if (!["style", "class", "id", "title", "alt", "width", "height", "colspan", "rowspan", "dir", "lang", "src"].includes(name) ||
          (name === "src" && !(node.tagName === "IMG" && /^data:image\/(png|jpeg|gif|webp);base64,/i.test(attribute.value)))) node.removeAttribute(attribute.name);
    }
  }
  return template.innerHTML;
}
function showBody(mail, htmlMode = false) {
  const target = $("mail-body"); target.replaceChildren();
  if (htmlMode && mail.body_html) {
    const frame = document.createElement("iframe");
    frame.title = "隔離されたHTMLメール";
    frame.setAttribute("sandbox", "");
    frame.referrerPolicy = "no-referrer";
    // No innerHTML interpolation into the parent, no scripts, no same-origin,
    // no network images/styles/fonts/forms, no popup/top-navigation privileges.
    // The CSP is first and cannot be relaxed by later email <meta> tags.
    frame.srcdoc = '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><style>body{overflow-wrap:anywhere;font:14px/1.6 sans-serif}img{max-width:100%}</style></head><body>' + safeHTML(mail.body_html) + '</body></html>';
    target.append(frame);
  } else target.append(element("pre", mail.body_text || "（本文なし）"));
}
async function showEmail(id) {
  const generation = ++detailGeneration;
  const mail = await api(`/api/emails/${id}`);
  if (generation !== detailGeneration) return;
  current = mail;
  const pane = $("preview"); pane.replaceChildren();
  pane.append(element("h2", mail.subject || "（件名なし）"));
  const recipients = mail.recipients.map(r => `${r.type.toUpperCase()}: ${r.name ? r.name + " " : ""}${r.address}`).join("\n");
  pane.append(element("div", `From: ${mail.sender}\n${recipients}\n${new Date(mail.date_ts * 1000).toLocaleString()}\n${mail.account_id} / ${mail.folder}\nMessage-ID: ${mail.message_id}`, "meta"));
  if (mail.has_attachments) pane.append(element("p", "添付ファイルあり。このUIでは添付をプレビューできないため、添付付き下書きの送信は無効です。"));
  const actions = element("div", undefined, "actions");
  const reply = element("button", "返信下書き"); reply.onclick = () => openEditor(mail); actions.append(reply);
  const thread = element("button", "スレッド"); thread.onclick = async () => {
    try {
      const rows = await api(`/api/emails/${mail.id}/thread`);
      const area = $("thread-list"); area.replaceChildren();
      for (const row of rows) { const b = element("button", `${new Date(row.date_ts * 1000).toLocaleString()} ${row.subject}`); b.onclick = () => showEmail(row.id).catch(fail); area.append(b); }
    } catch (e) { fail(e); }
  }; actions.append(thread);
  if (mail.body_html) {
    let mode = false; const toggle = element("button", "HTML表示（外部画像は遮断）");
    toggle.onclick = () => { mode = !mode; toggle.textContent = mode ? "テキスト表示" : "HTML表示（外部画像は遮断）"; showBody(mail, mode); }; actions.append(toggle);
  }
  if (mail.is_draft) {
    const send = element("button", mail.send_state ? `送信処理済み: ${mail.send_state}` : "確認して送信", "primary");
    send.disabled = Boolean(mail.send_state) || mail.has_attachments;
    send.onclick = async () => {
      if (!window.confirm(`この下書きをSMTPで送信しますか？\nFrom: ${mail.sender}\n${recipients}\n件名: ${mail.subject}`)) return;
      send.disabled = true;
      try {
        const result = await api(`/api/drafts/${mail.id}/send`, {method: "POST", headers: {"X-Confirm-Send": "human-reviewed"}});
        status(result.state === "accepted" ? "SMTPサーバーが受け付けました。下書きは保持されます。" : `一部宛先は拒否されました: ${result.refused.join(", ")}。自動再送しません。`, result.state !== "accepted");
        await showEmail(mail.id);
      } catch (e) { fail(e); await showEmail(mail.id).catch(() => {}); }
    }; actions.append(send);
  }
  pane.append(actions);
  const threads = element("div"); threads.id = "thread-list"; pane.append(threads);
  const body = element("div"); body.id = "mail-body"; pane.append(body); showBody(mail);
}
function openEditor(mail = null) {
  replyId = mail ? mail.id : null;
  $("draft-account").value = mail ? mail.account_id : (accountId || accounts.find(a => a.enabled)?.id || "");
  $("draft-account").disabled = Boolean(mail);
  // A reply address is only a suggestion and remains visibly editable.
  const address = mail ? (mail.reply_to || mail.sender) : "";
  const match = address.match(/<([^<>]+)>/);
  $("draft-to").value = match ? match[1] : address;
  $("draft-subject").value = mail ? (/^re:/i.test(mail.subject) ? mail.subject : `Re: ${mail.subject}`) : "";
  $("draft-body").value = mail ? `\n\n${mail.sender}:\n${mail.body_text.slice(0, 50000).split("\n").map(x => "> " + x).join("\n")}` : "";
  $("draft-error").textContent = ""; $("editor").showModal();
}
$("login").addEventListener("cancel", event => event.preventDefault());
$("login-form").onsubmit = async event => {
  event.preventDefault(); token = $("token").value.trim();
  try { await refresh(); $("token").value = ""; $("login").close(); status("接続済み。件数はローカルキャッシュ基準です。閲覧による既読変更は行いません。"); await offerUnlock(); }
  catch (e) { token = ""; $("login-error").textContent = e.message; }
};
$("logout").onclick = () => location.reload();
$("compose").onclick = () => openEditor();
$("cancel-draft").onclick = () => $("editor").close();
$("draft-form").onsubmit = async event => {
  event.preventDefault(); $("save-draft").disabled = true;
  try {
    await api("/api/drafts", {method: "POST", body: JSON.stringify({account_id: $("draft-account").value, to: $("draft-to").value.split(",").map(x => x.trim()).filter(Boolean), subject: $("draft-subject").value, body: $("draft-body").value, reply_to_email_id: replyId})});
    $("editor").close(); status("下書きを保存しました。同期後、Draftsフォルダから開いて確認・送信してください。");
  } catch (e) { $("draft-error").textContent = e.message; }
  finally { $("save-draft").disabled = false; }
};
$("search-form").onsubmit = event => { event.preventDefault(); loadMessages().catch(fail); };
$("all").onclick = () => { accountId = null; folder = null; refresh().catch(fail); };
$("more").onclick = () => loadMessages(true).catch(fail);
$("sync").onclick = async () => { try { await api("/api/sync", {method: "POST"}); status("同期を要求しました。数秒後に一覧を更新します。"); } catch (e) { fail(e); } };
let syncErrorShown = false;
setInterval(async () => {
  if (!token || $("editor").open || $("settings-dialog").open || $("login").open || document.hidden) return;
  try {
    await loadAccounts();
    // Reloading resets to page 1; keep the list while the user has paged further.
    if (offset <= pageSize) await loadMessages();
    const states = await api("/api/sync");
    const errors = Object.entries(states).filter(([, value]) => !value.ok);
    if (errors.length) {
      status(`同期エラー: ${errors.map(([id, value]) => `${id}: ${value.error}`).join(" / ")}。接続・フォルダ設定を確認してください。`, true);
      syncErrorShown = true;
    } else if (syncErrorShown) {
      status("同期は正常に戻りました。");
      syncErrorShown = false;
    }
  } catch (e) { fail(e); }
}, 15000);
$("login").showModal();

let accountState = null;
function clearAccountSecrets() {
  for (const id of ["master-password", "master-confirm", "imap-password", "smtp-password"]) $(id).value = "";
}
function selectAccount(id = "") {
  const account = accountState.accounts.find(a => a.id === id);
  $("account-choice").value = account ? id : "";
  $("account-id").value = account?.id || "";
  $("account-id").readOnly = Boolean(account);
  $("account-name").value = account?.name || "";
  $("account-email").value = account?.email || "";
  $("account-enabled").checked = account ? account.enabled : true;
  $("account-folders").value = account?.folders.join("\n") || "INBOX";
  $("account-drafts").value = account?.drafts_folder || "";
  for (const kind of ["imap", "smtp"]) {
    const endpoint = account?.[kind];
    $(kind + "-host").value = endpoint?.host || "";
    $(kind + "-port").value = endpoint?.port || (kind === "imap" ? 993 : 465);
    $(kind + "-security").value = endpoint?.security || "tls";
    $(kind + "-username").value = endpoint?.username || "";
    $(kind + "-password").value = "";
    $(kind + "-password").required = !endpoint?.has_password;
    $(kind + "-password").placeholder = endpoint?.has_password ? "登録済み（変更しない場合は空欄）" : "新しいパスワードを入力";
  }
}
function renderAccountSettings(state, selection = "") {
  accountState = state;
  $("vault-status").textContent = state.encrypted ? (state.locked ? "暗号化済み・ロック中。解除するとメール同期を開始します。" : "暗号化済み・ロック解除中。このサーバーを停止すると再びロックされます。") : "初回設定：マスターパスワードを決めて、既存のメールパスワードを暗号化してください。";
  $("unlock-form").classList.toggle("hidden", !state.locked);
  $("master-confirm-label").classList.toggle("hidden", state.encrypted);
  $("master-confirm").required = !state.encrypted;
  $("master-password").minLength = state.encrypted ? 1 : 12;
  $("unlock-button").textContent = state.encrypted ? "ロックを解除" : "暗号化を開始（既存設定も移行）";
  $("vault-help").textContent = state.encrypted ? "起動後に一度、マスターパスワードを入力してください。" : "12文字以上の長く推測されにくいパスワードを設定してください。既存のIMAP/SMTPパスワードは保持したまま暗号化します。";
  $("account-fields").disabled = state.locked;
  $("account-choice").replaceChildren();
  const fresh = element("option", "新しく登録する"); fresh.value = ""; $("account-choice").append(fresh);
  for (const account of state.accounts) {
    const option = element("option", `${account.name} (${account.email})${account.enabled ? "" : "・無効"}`);
    option.value = account.id; $("account-choice").append(option);
  }
  selectAccount(selection);
}
async function openAccountSettings(initialState = null) {
  clearAccountSecrets(); $("settings-error").textContent = "";
  renderAccountSettings(initialState || await api("/api/settings"));
  if (!$("settings-dialog").open) $("settings-dialog").showModal();
}
async function offerUnlock() {
  try {
    const state = await api("/api/settings");
    if (state.locked || !state.accounts.some(a => a.enabled)) await openAccountSettings(state);
  } catch (e) { fail(e); }
}
$("account-settings").onclick = () => openAccountSettings().catch(fail);
$("account-choice").onchange = () => selectAccount($("account-choice").value);
$("close-settings").onclick = () => $("settings-dialog").close();
$("settings-dialog").addEventListener("close", clearAccountSecrets);
$("unlock-form").onsubmit = async event => {
  event.preventDefault(); $("unlock-button").disabled = true; $("settings-error").textContent = "";
  try {
    const result = await api("/api/settings/unlock", {method: "POST", body: JSON.stringify({master_password: $("master-password").value, confirmation: accountState.encrypted ? null : $("master-confirm").value})});
    clearAccountSecrets(); renderAccountSettings(result);
    status("ロックを解除しました。有効なアカウントの同期を開始します。");
    await refresh();
  } catch (e) { $("settings-error").textContent = e.message; }
  finally { $("master-password").value = ""; $("master-confirm").value = ""; $("unlock-button").disabled = false; }
};
$("account-form").onsubmit = async event => {
  event.preventDefault(); $("save-account").disabled = true; $("settings-error").textContent = "";
  const input = {id: $("account-id").value.trim(), name: $("account-name").value.trim(), email: $("account-email").value.trim(), enabled: $("account-enabled").checked, folders: $("account-folders").value.split("\n").map(v => v.trim()).filter(Boolean), drafts_folder: $("account-drafts").value.trim() || null};
  for (const kind of ["imap", "smtp"]) input[kind] = {host: $(kind + "-host").value.trim(), port: Number($(kind + "-port").value), username: $(kind + "-username").value.trim(), security: $(kind + "-security").value, password: $(kind + "-password").value};
  try {
    const result = await api(`/api/settings/accounts/${encodeURIComponent(input.id)}`, {method: "PUT", body: JSON.stringify(input)});
    clearAccountSecrets(); renderAccountSettings(result, input.id);
    $("vault-status").textContent = "暗号化して保存しました。設定は再起動せず反映されます。";
    status("アカウントを保存しました。接続結果は同期ステータスで確認できます。");
    await refresh();
  } catch (e) { $("settings-error").textContent = e.message; }
  finally { $("save-account").disabled = false; }
};
