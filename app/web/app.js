const $ = (id) => document.getElementById(id);

let currentVersion = 0;
let pollTimer = null;

const STATUS_LABEL = {
  free: "空闲",
  offered: "已预留 (OFFER)",
  bound: "已确认 (ACK)",
  declined: "隔离中 (DECLINE)",
};

const ACTION_LABEL = {
  DHCPOFFER: "已返回 OFFER",
  DHCPACK: "已返回 ACK",
  DHCPNAK: "已返回 NAK（地址不可用）",
};

function setHealth(ok, text) {
  const el = $("health");
  el.textContent = text;
  el.className = "health " + (ok ? "ok" : "bad");
}

function fmtRemaining(sec) {
  if (sec <= 0) return "0s";
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return m > 0 ? `${m}m ${String(s).padStart(2, "0")}s` : `${s}s`;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function renderPool(state) {
  const { config, stats, leases } = state;
  const byIp = new Map(leases.map((l) => [l.ip, l]));
  const start = ipToInt(config.pool_start);
  const end = ipToInt(config.pool_end);
  const chips = [];
  for (let n = start; n <= end; n++) {
    const ip = intToIp(n);
    const lease = byIp.get(ip);
    const status = lease ? lease.status : "free";
    let meta = STATUS_LABEL[status];
    if (lease) {
      const who = lease.hostname || lease.client_mac || lease.client_key;
      meta += ` · ${who} · ${fmtRemaining(lease.remaining_seconds)}`;
    }
    chips.push(`<div class="chip ${status}"><span class="ip">${esc(ip)}</span><span class="meta">${esc(meta)}</span></div>`);
  }
  $("pool").innerHTML = chips.join("");
  $("config").innerHTML = [
    `<span>范围 <b>${esc(config.pool_start)} – ${esc(config.pool_end)}</b></span>`,
    `<span>子网 <b>${esc(config.subnet_mask)}</b></span>`,
    `<span>路由 <b>${esc(config.router)}</b></span>`,
    `<span>服务器 <b>${esc(config.server_id)}</b></span>`,
    `<span>租期 <b>${config.lease_time}s</b></span>`,
    `<span>OFFER 有效 <b>${config.offer_ttl}s</b></span>`,
    `<span>UDP <b>${config.udp_port}</b></span>`,
    `<span>空闲 <b>${stats.free}/${stats.pool_size}</b></span>`,
  ].join("");
}

function ipToInt(ip) {
  return ip.split(".").reduce((acc, part) => acc * 256 + Number(part), 0);
}
function intToIp(n) {
  return [24, 16, 8, 0].map((shift) => Math.floor(n / 2 ** shift) % 256).join(".");
}

function renderLeases(leases) {
  $("lease-count").textContent = `${leases.length} 条`;
  if (!leases.length) {
    $("leases").innerHTML = `<tr><td colspan="7" class="empty">暂无预留或租约</td></tr>`;
    return;
  }
  $("leases").innerHTML = leases.map((l) => `
    <tr>
      <td>${esc(l.ip)}</td>
      <td><span class="tag ${esc(l.status)}">${esc(STATUS_LABEL[l.status] || l.status)}</span></td>
      <td>${esc(l.client_key)}</td>
      <td>${esc(l.client_mac || "—")}</td>
      <td>${esc(l.hostname || "—")}</td>
      <td>${esc(fmtRemaining(l.remaining_seconds))}</td>
      <td>${esc(l.updated_at)}</td>
    </tr>`).join("");
}

function renderEvents(events) {
  if (!events.length) {
    $("events").innerHTML = `<tr><td colspan="6" class="empty">暂无事件</td></tr>`;
    return;
  }
  $("events").innerHTML = events.map((e) => `
    <tr>
      <td>${esc(e.at)}</td>
      <td>${esc(e.category)}</td>
      <td>${esc(e.message_type || "—")}</td>
      <td>${esc(e.ip || "—")}</td>
      <td>${esc(e.client_key || "—")}</td>
      <td class="detail">${esc(JSON.stringify(e.detail))}</td>
    </tr>`).join("");
}

async function refresh() {
  try {
    const res = await fetch("/api/state?ts=" + Date.now(), { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const state = await res.json();
    currentVersion = state.version;
    setHealth(true, `服务正常 · UDP ${state.config.udp_port} · 空闲 ${state.stats.free}/${state.stats.pool_size}`);
    renderPool(state);
    renderLeases(state.leases);
    renderEvents(state.events);
  } catch (err) {
    setHealth(false, "服务不可达: " + err.message);
  }
}

async function longPoll() {
  try {
    const res = await fetch(`/api/state/wait?after=${currentVersion}`, { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      if (data.version !== currentVersion) refresh();
    }
  } catch (_) {
    /* retry below */
  } finally {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(longPoll, 1500);
  }
}

function updateTargetFields() {
  const custom = $("target").value === "custom";
  $("target_host").disabled = !custom;
  $("target_port").disabled = !custom;
}

function updateActionFields() {
  const kind = $("kind").value;
  const request = kind === "REQUEST";
  const release = kind === "RELEASE";
  $("requested_ip").disabled = !request;
  $("ciaddr").disabled = !(request || release);
}

function formBody() {
  const xidRaw = $("xid").value.trim();
  const portRaw = $("target_port").value.trim();
  const body = {
    kind: $("kind").value,
    mac: $("mac").value.trim(),
    hostname: $("hostname").value.trim() || null,
    requested_ip: $("requested_ip").value.trim() || null,
    ciaddr: $("ciaddr").value.trim() || null,
    server_id: $("server_id").value.trim() || null,
    use_client_id: $("use_client_id").checked,
    target: $("target").value,
  };
  if (xidRaw) body.xid = Number(xidRaw);
  if (body.target === "custom") {
    body.target_host = $("target_host").value.trim();
    body.target_port = portRaw ? Number(portRaw) : null;
  }
  return body;
}

async function sendPacket(body) {
  const status = $("sim-status");
  const buttons = document.querySelectorAll("#sim-form button");
  buttons.forEach((b) => (b.disabled = true));
  status.textContent = "发送中…";
  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    status.textContent = data.action
      ? ACTION_LABEL[data.action] || data.action
      : data.note;
    const box = $("sim-result");
    box.classList.remove("hidden");
    box.textContent = JSON.stringify(
      {
        目标: data.target,
        说明: data.note,
        动作: data.action,
        响应: data.reply,
        发送报文: data.sent_hex,
      },
      null,
      2
    );
    refresh();
  } catch (err) {
    status.textContent = "失败: " + err.message;
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

$("kind").addEventListener("change", updateActionFields);
$("target").addEventListener("change", updateTargetFields);
$("sim-form").addEventListener("submit", (e) => {
  e.preventDefault();
  sendPacket(formBody());
});
$("quick-discover").addEventListener("click", () => {
  $("kind").value = "DISCOVER";
  updateActionFields();
  sendPacket(formBody());
});

updateTargetFields();
updateActionFields();
refresh().then(() => longPoll());
setInterval(refresh, 10000);
