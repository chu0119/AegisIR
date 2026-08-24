/* AegisIR v2.1 控制台逻辑 */
"use strict";

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const VIEWS = {
  scan:     "探测目标",
  iso:      "隔离监控",
  history:  "历史审计",
  nodes:    "节点管理",
  settings: "设置",
};
const DEFAULT_SETTINGS = { defMode: "offnet", defDur: 30, interval: 1.0, fakeMac: "" };
const MODE_INFO = {
  offnet: { label: "断外网 · 影响面最小（推荐首选）",
            desc: "切断目标与网关通信：无法访问互联网与跨网段，同网段邻居不受影响。" },
  island: { label: "彻底断网 · 同网段全断",
            desc: "断外网基础上，切断目标与同网段所有主机的双向通信，彻底成为孤岛。" },
};

const state = {
  nodes: JSON.parse(localStorage.getItem("aegis_nodes") || "[]"),
  cur: null,
  view: "scan",
  doctor: null,
  interfaces: [],
  iface: "",
  scan: null,
  active: [],
  sessions: [],
  events: [],
  target: null,        // {ip, mac} 或 {batch: [ip...]}
  filter: "",
  checked: new Set(),
  deployToken: "",
  nodeHealth: {},      // url -> bool 在线状态
  settings: { ...DEFAULT_SETTINGS, ...(JSON.parse(localStorage.getItem("aegis_settings") || "{}")) },
};

function saveSettings() {
  localStorage.setItem("aegis_settings", JSON.stringify(state.settings));
}

/* ═══════════ 基础工具 ═══════════ */
function base() { return state.cur ? state.cur.url : ""; }
function token() { return state.cur ? (state.cur.token || "") : ""; }

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (token()) headers["X-Aegis-Token"] = token();
  const r = await fetch(base() + path, { ...opts, headers });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}
function ipToInt(ip) { return ip.split(".").reduce((n, x) => ((n << 8) + (+x)) >>> 0, 0); }
function inSubnet(ip, cidr) {
  try {
    const [net, plen] = cidr.split("/");
    const mask = +plen === 0 ? 0 : (0xffffffff << (32 - +plen)) >>> 0;
    return (ipToInt(ip) & mask) === (ipToInt(net) & mask);
  } catch (e) { return false; }
}
function isIpv4(s) { return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split(".").every(x => +x <= 255); }
function fmtElapsed(sec) {
  sec = Math.max(0, sec | 0);
  const h = (sec / 3600) | 0, m = ((sec % 3600) / 60) | 0, s = sec % 60;
  const p = (n) => String(n).padStart(2, "0");
  return h ? `${h}:${p(m)}:${p(s)}` : `${p(m)}:${p(s)}`;
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function toast(msg, cls = "") {
  const el = document.createElement("div");
  el.className = "toast " + cls;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), 4800);
}
function curIface() {
  return state.interfaces.find(i => i.id === state.iface) || null;
}
function genToken() {
  const buf = new Uint8Array(9);
  crypto.getRandomValues(buf);
  return [...buf].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta);
      ta.select(); document.execCommand("copy"); ta.remove();
      return true;
    } catch (e2) { return false; }
  }
}

/* ═══════════ 视图切换 ═══════════ */
function switchView(name) {
  state.view = name;
  $$(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.view === name));
  Object.keys(VIEWS).forEach(v => $("#view-" + v).classList.toggle("hidden", v !== name));
  $("#viewTitle").textContent = VIEWS[name];
}

/* ═══════════ 节点管理 ═══════════ */
function saveNodes() { localStorage.setItem("aegis_nodes", JSON.stringify(state.nodes)); }

function renderNodeSelect() {
  const sel = $("#nodeSelect");
  sel.innerHTML = "";
  const local = document.createElement("option");
  local.value = "";
  local.textContent = "本机节点" + (state.doctor ? `（${state.doctor.onlink || "?"}）` : "");
  sel.appendChild(local);
  state.nodes.forEach((n, i) => {
    const o = document.createElement("option");
    o.value = String(i);
    o.textContent = n.name || n.url;
    sel.appendChild(o);
  });
  sel.value = state.cur ? String(state.cur._idx) : "";
}

function renderNodeList() {
  const box = $("#nodeList");
  if (!state.nodes.length) {
    box.innerHTML = '<div class="hint">尚未接入其他节点。跨网段目标请先按上方指引一行命令部署节点。</div>';
    return;
  }
  box.innerHTML = state.nodes.map((n, i) => {
    const on = state.nodeHealth[n.url];
    return `
    <div class="node-row">
      <span class="dot ${on === true ? "ok" : on === false ? "" : ""}"></span>
      <b>${esc(n.name)}</b>
      <span class="url">${esc(n.url)}</span>
      <span class="st">${on === true ? "在线" : on === false ? "离线" : "检测中"}</span>
      ${state.cur && state.cur._idx === i ? '<span class="tag">当前</span>' : ""}
      <button class="btn sm" data-use="${i}">切换</button>
      <button class="btn sm ghost" data-del="${i}">移除</button>
    </div>`;
  }).join("");
  box.querySelectorAll("[data-use]").forEach(b => b.addEventListener("click", async () => {
    await switchNodeByIndex(+b.dataset.use);
  }));
  box.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", () => {
    const i = +b.dataset.del;
    if (!confirm(`移除节点 ${state.nodes[i].name || state.nodes[i].url}？`)) return;
    const was = state.cur && state.cur._idx === i;
    state.nodes.splice(i, 1);
    saveNodes();
    if (was) state.cur = null;
    renderNodeSelect(); renderNodeList(); refreshAll();
  }));
}

async function switchNodeByIndex(idx) {
  const n = state.nodes[idx];
  if (!n) return;
  state.cur = { ...n, _idx: idx };
  try {
    await api("/api/doctor");
    toast(`已切换到节点 ${n.name || n.url}`, "ok");
  } catch (e) {
    toast(`节点连接失败: ${e.message}`, "err");
  }
  renderNodeSelect(); renderNodeList(); refreshAll();
}

function deployBase() {
  const d = state.doctor;
  const ip = d && d.ip ? d.ip : location.hostname || "127.0.0.1";
  const port = location.port || (location.protocol === "https:" ? "443" : "80");
  return `http://${ip}:${port}`;
}

function renderDeploy() {
  if (!state.deployToken) state.deployToken = genToken();
  const t = state.deployToken;
  const base = deployBase();
  $("#cmdSh").textContent =
    `curl -fsSL "${base}/deploy/install.sh?token=${t}" | sudo bash`;
  $("#cmdPs").textContent =
    `powershell -ExecutionPolicy Bypass -c "iwr '${base}/deploy/install.ps1?token=${t}' -OutFile aegis-setup.ps1; .\\aegis-setup.ps1"`;
  $("#tokenShow").textContent = t;
  const warn = $("#deployWarn");
  const d = state.doctor;
  if (d && d.listen && d.listen !== "0.0.0.0") {
    warn.classList.remove("hidden");
    warn.innerHTML = "控制台当前仅本机监听，目标机器无法访问部署地址。请在<b>本控制台机器</b>上重启为对外监听（重启后刷新本页）：<br>" +
      `<code class="mono">AegisIR.exe gui --listen any --token ${t}</code>` +
      "&nbsp;<button id='warnCopy' class='btn sm'>复制重启命令</button>";
    const wc = $("#warnCopy");
    if (wc) wc.addEventListener("click", async () => {
      const ok = await copyText(`AegisIR.exe gui --listen any --token ${t}`);
      toast(ok ? "已复制，请关闭当前控制台后以该命令重启" : "复制失败", ok ? "ok" : "err");
    });
  } else {
    warn.classList.add("hidden");
  }
}

async function addNodeSubmit() {
  const url = $("#nmUrl").value.trim().replace(/\/+$/, "");
  const t = $("#nmToken").value.trim();
  const name = $("#nmName").value.trim();
  if (!/^https?:\/\/.+/.test(url)) return toast("节点地址应为 http://IP:端口", "err");
  const btn = $("#nmOk");
  btn.disabled = true; btn.textContent = "测试中 …";
  try {
    const r = await fetch(url + "/api/doctor", { headers: t ? { "X-Aegis-Token": t } : {} });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const d = await r.json();
    state.nodes.push({ name: name || d.node || url, url, token: t });
    saveNodes();
    toast(`节点接入成功（网段 ${d.onlink || "?"}）`, "ok");
    $("#nodeModal").classList.add("hidden");
    renderNodeSelect(); renderNodeList();
  } catch (e) {
    toast("连接节点失败: " + e.message, "err");
  } finally {
    btn.disabled = false; btn.textContent = "测试并接入";
  }
}

/* ═══════════ 渲染：顶栏 / 环境 ═══════════ */
function renderDoctor() {
  const d = state.doctor;
  if (!d) return;
  const pill = (ok, text, warn) =>
    `<span class="pill ${ok ? "ok" : warn ? "warn" : "bad"}">${text}</span>`;
  $("#pills").innerHTML =
    (d.raw_ok ? pill(true, "完整引擎") : pill(false, "兼容引擎", !d.admin)) +
    pill(d.admin, "管理员") +
    pill(true, `端口 ${location.port}`) +
    (d.onlink ? pill(true, d.onlink) : pill(false, "网段未知")) +
    (d.gateway_ip ? pill(true, "网关 " + d.gateway_ip) : pill(false, "网关未知"));

  // 更新浏览器标签页标题，显示管理员状态和端口
  document.title = `AegisIR :${location.port}${d.admin ? "" : " ⚠非管理员"}`;

  const banner = $("#banner");
  if (!d.admin) {
    banner.classList.remove("hidden");
    banner.className = "banner critical";
    banner.innerHTML = "🚫 <b>未以管理员运行 — 隔离功能完全不可用</b>　探测仍可用（兼容引擎），但 ARP 阻断需要管理员权限发原始数据包。" +
      "　<b>解决方法</b>：关闭所有 AegisIR 窗口和终端，右键「以管理员身份运行」AegisIR.exe 或终端重新启动。";
  } else if (!d.pcap_ok) {
    banner.classList.remove("hidden");
    banner.className = "banner critical";
    banner.innerHTML = "🚫 <b>Npcap 抓包驱动不可用</b>　隔离功能依赖 Npcap。请到 <a href='https://npcap.com' target='_blank' style='color:#ffd39a'>npcap.com</a> 下载安装后重启。";
  } else {
    banner.classList.add("hidden");
  }

  const eng = $("#engineBadge");
  eng.className = "engine " + (d.raw_ok ? "" : "compat");
  eng.textContent = d.raw_ok ? "完整引擎 raw" : "兼容引擎 compat";
  updateEngineUI();

  $("#envBody").innerHTML = `
    <dt>节点名称</dt><dd>${esc(d.node)}</dd>
    <dt>本机 IP</dt><dd>${esc(d.ip) || "-"} / ${esc(d.mac) || "-"}</dd>
    <dt>直连网段</dt><dd>${esc(d.onlink) || "未知"}</dd>
    <dt>网关</dt><dd>${esc(d.gateway_ip) || "-"} / ${esc(d.gateway_mac) || "-"}</dd>
    <dt>引擎</dt><dd>${d.raw_ok ? "raw（scapy 原始报文）" : "compat（免权限）"}</dd>
    <dt>Scapy</dt><dd>${esc(d.scapy)}</dd>`;
  renderNodeSelect();
  renderDeploy();
}

/* ═══════════ 渲染：网卡 ═══════════ */
function renderInterfaces() {
  const sel = $("#ifaceSel");
  const prev = state.iface;
  sel.innerHTML = state.interfaces.map(i =>
    `<option value="${esc(i.id)}" ${i.id === prev ? "selected" : ""}>` +
    `${i.is_default ? "★ " : ""}${esc(i.name)} · ${esc(i.ip)}</option>`).join("");
  if (!prev && state.interfaces.length) {
    const def = state.interfaces.find(i => i.is_default) || state.interfaces[0];
    state.iface = def.id;
    sel.value = def.id;
  }
  prefillNet();
}

function prefillNet() {
  const ifc = curIface();
  if (!ifc) return;
  const input = $("#netInput");
  if (ifc.network) {
    const plen = +ifc.network.split("/")[1] || 24;
    input.value = plen >= 22 ? ifc.network
      : ifc.ip.split(".").slice(0, 3).join(".") + ".0/24";
    $("#scanHint").textContent = `${ifc.name} 直连 ${ifc.network}` +
      (plen < 22 ? "（较大，已预填 /24，可改用 IP 范围精确切片）" : "") +
      (ifc.gateway ? ` · 网关 ${ifc.gateway}` : "");
  }
}

function updateEngineUI() {
  const eng = $("#engineSel").value;
  const rawAvail = state.doctor ? state.doctor.raw_ok : false;
  const show = eng === "raw" || (eng === "auto" && rawAvail);
  $("#rawMethods").classList.toggle("hidden", !show);
  $("#optPassive").disabled = eng === "raw";
}

/* ═══════════ 渲染：扫描 ═══════════ */
let _hostsFingerprint = "";  // 上次渲染的稳定指纹，防止轮询重建 DOM 导致勾选丢失

function renderScan() {
  const s = state.scan;
  if (!s) return;
  const p = $("#scanProgress");
  if (s.running) {
    p.classList.remove("hidden");
    const [done, total] = s.progress || [0, 0];
    p.querySelector(".txt").textContent =
      `${s.stage || "探测中"} ${total ? Math.round(done / total * 100) + "%" : ""} · 请稍候`;
    $("#scanBtn").disabled = true;
  } else {
    p.classList.add("hidden");
    $("#scanBtn").disabled = false;
    if (s.error) $("#scanHint").textContent = "上次探测失败: " + s.error;
  }
  renderHosts(s.last);
}

function hostMatches(ip, h) {
  const f = state.filter.toLowerCase();
  if (!f) return true;
  return (ip + " " + (h.hostname || "") + " " + (h.vendor || "") + " " + (h.mac || "") + " " + inferType(h))
    .toLowerCase().includes(f);
}

/** 根据厂商+端口推断设备类型 */
function inferType(h) {
  const ports = new Set([...(h.ports || []).map(x => x.port), ...(h.tcp_ping_ports || [])]);
  const vendor = (h.vendor || "").toLowerCase();
  const hostname = (h.hostname || "").toLowerCase();
  if (h.is_gateway) return "网关/路由";
  if (h.is_self) return "本机";
  if (ports.has(554) || /hikvision|dahua|axis|onvif/.test(vendor)) return "摄像头";
  if (ports.has(9100) || /printer|hp|canon|epson|brother/.test(vendor)) return "打印机";
  if (/synology|qnap|western digital/.test(vendor) || (ports.has(445) && ports.has(5000))) return "NAS";
  if (/vmware|qemu|kvm|virtual|hyper-v/.test(vendor) || /vm|virt/.test(hostname)) return "虚拟机";
  if (/raspberry|arduino|esp32/.test(vendor)) return "IoT/嵌入式";
  if (ports.has(3389) && ports.has(445)) return "Windows 主机";
  if (ports.has(22) && !ports.has(3389)) return "Linux 主机";
  if (ports.has(445)) return "Windows 主机";
  if (ports.has(80) || ports.has(443)) return "Web 服务";
  return "未知";
}

function renderHosts(data, force = false) {
  const tbody = $("#hostsTable tbody");

  // 稳定指纹：scan_time + 主机 IP 列表 + 筛选条件
  // 同一轮询周期内数据不变则跳过 DOM 重建（勾选状态不被销毁）
  const fp = data
    ? `${data.scan_time}|${Object.keys(data.hosts || {}).sort().join(",")}|${state.filter}`
    : `empty|${state.filter}`;
  if (!force && fp === _hostsFingerprint && tbody.children.length > 0) return;
  _hostsFingerprint = fp;

  // 保留当前勾选状态
  const prevChecked = new Set(state.checked);

  if (!data || !Object.keys(data.hosts || {}).length) {
    tbody.innerHTML = `<tr class="empty"><td colspan="10">${
      data ? "未发现存活主机（可尝试更大范围或深度端口）" : "暂无数据 · 请先选择网卡与目标开始探测"}</td></tr>`;
    $("#hostsMeta").textContent = "";
    state.checked.clear();
    updateBatchBtn();
    return;
  }
  const eng = data.engine || "";
  $("#hostsMeta").textContent =
    `${Object.keys(data.hosts).length} 台 · ${data.cidr} · ${data.scan_time} · ${eng}` +
    (data.segment === "routed" ? " · 跨网段" : "");
  const rows = [];
  let i = 0;
  for (const [ip, h] of Object.entries(data.hosts)) {
    i++;
    if (!hostMatches(ip, h)) continue;
    const dtype = inferType(h);
    const tags = [];
    tags.push(`<span class="tag ${dtype === "未知" ? "" : "type"}">${esc(dtype)}</span>`);
    if (h.is_gateway) tags.push('<span class="tag lock">网关 🔒</span>');
    if (h.is_self) tags.push('<span class="tag lock">本机 🔒</span>');
    if (data.segment === "routed" && !h.is_self) tags.push('<span class="tag far">跨网段</span>');
    const chips = (h.hits || []).map(x => `<span class="chip ${esc(x)}">${esc(x)}</span>`).join("") || '<span class="hint">-</span>';
    const ports = (h.ports || []).map(x => `${x.port}/${esc(x.service)}`).slice(0, 5).join(" ")
      || ((h.tcp_ping_ports || []).length ? h.tcp_ping_ports.join(" ") : "-");
    const locked = h.is_gateway || h.is_self;
    const wasChecked = prevChecked.has(ip);
    rows.push(`<tr data-dip="${esc(ip)}" title="点击查看设备详情" ${wasChecked ? 'class="marked"' : ""}>
      <td class="cb">${locked ? "" : `<input type="checkbox" data-bip="${esc(ip)}" ${wasChecked ? "checked" : ""}>`}</td>
      <td>${i}</td><td class="ip">${esc(ip)}</td><td>${esc(h.mac) || "-"}</td>
      <td>${esc((h.vendor || "-").slice(0, 16))}</td><td>${esc((h.hostname || "-").slice(0, 22))}</td>
      <td>${chips}</td><td>${esc(ports)}</td><td>${tags.join(" ")}</td>
      <td>${locked ? '<button class="btn sm" disabled title="网关/本机禁止隔离">🔒</button>'
                   : `<button class="btn sm danger" data-ip="${esc(ip)}" data-mac="${esc(h.mac || "")}">隔离</button>`}</td>
    </tr>`);
  }
  tbody.innerHTML = rows.length ? rows.join("")
    : `<tr class="empty"><td colspan="10">没有匹配筛选条件的主机</td></tr>`;
  bindTableEvents(tbody);
  // 恢复全选框状态
  const allCbs = tbody.querySelectorAll("input[data-bip]");
  $("#selAll").checked = allCbs.length > 0 && allCbs.length === state.checked.size;
}

function bindTableEvents(tbody) {
  tbody.querySelectorAll("button[data-ip]").forEach(b =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      openModal(b.dataset.ip, b.dataset.mac);
    }));
  tbody.querySelectorAll("input[data-bip]").forEach(b => {
    b.addEventListener("click", (e) => e.stopPropagation());
    b.addEventListener("change", () => {
      if (b.checked) state.checked.add(b.dataset.bip);
      else state.checked.delete(b.dataset.bip);
      b.closest("tr").classList.toggle("marked", b.checked);
      updateBatchBtn();
    });
  });
  tbody.querySelectorAll("tr[data-dip]").forEach(tr =>
    tr.addEventListener("click", () => openDrawer(tr.dataset.dip)));
}

function updateBatchBtn() {
  const n = state.checked.size;
  $("#batchCount").textContent = n;
  $("#batchBtn").classList.toggle("hidden", n === 0);
}

function exportCsv() {
  const data = state.scan && state.scan.last;
  if (!data || !Object.keys(data.hosts).length) return toast("没有可导出的数据", "err");
  const head = ["IP", "设备类型", "MAC", "厂商", "主机名", "命中手段", "开放端口", "网关", "本机", "扫描时间", "网段", "引擎"];
  const lines = [head.join(",")];
  for (const [ip, h] of Object.entries(data.hosts)) {
    lines.push([
      ip, inferType(h), h.mac || "", (h.vendor || "").replace(",", " "), (h.hostname || "").replace(",", " "),
      (h.hits || []).join("/"),
      (h.ports || []).map(x => x.port + "/" + x.service).join(" "),
      h.is_gateway ? "是" : "", h.is_self ? "是" : "",
      data.scan_time, data.cidr, data.engine || "",
    ].map(x => `"${String(x).replace(/"/g, '""')}"`).join(","));
  }
  const blob = new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `aegis_scan_${data.cidr.replace(/[\\/]/g, "-")}_${Date.now()}.csv`;
  a.click();
  toast("CSV 已导出（含 BOM，Excel 直接打开）", "ok");
}

/* ═══════════ 渲染：隔离视图 ═══════════ */
function renderActive() {
  const list = $("#activeList");
  const empty = $("#isoEmpty");
  const badge = $("#isoBadge");
  badge.textContent = state.active.length;
  badge.classList.toggle("hidden", !state.active.length);
  if (!state.active.length) {
    empty.classList.remove("hidden");
    list.innerHTML = "";
    return;
  }
  empty.classList.add("hidden");
  list.innerHTML = state.active.map(a => {
    const verify = a.arp_requests !== undefined && !a.dry_run
      ? (a.verified
          ? `<span class="verify ok" title="已观察到目标反复广播网关 ARP 请求">隔离生效确认</span>`
          : `<span class="verify wait" title="尚未观察到目标 ARP 广播（可能目标不在线或 compat 引擎无验证）">生效验证中</span>`)
      : "";
    return `
    <div class="active-item">
      <div>
        <div class="ip">${esc(a.victim_ip)} ${a.dry_run ? '<span class="tag drill">演练</span>' : ""}</div>
        <div class="hint">${esc(a.victim_mac)}</div>
      </div>
      <div class="info">
        模式 <b>${a.mode === "island" ? "彻底断网" : "断外网"}</b> ·
        累计发包 <b>${a.sent}</b>${verify ? "<br>" + verify : ""}<br>
        <span class="hint">${a.arp_requests ? `目标 ARP 广播 ${a.arp_requests} 次` : "目标 ARP 广播 0 次（未生效或不可验证）"}</span>
      </div>
      <div style="text-align:center">
        <div class="timer">${fmtElapsed(a.elapsed)}</div>
        <div class="hint">已隔离时长</div>
      </div>
      <button class="btn ok" data-ip="${esc(a.victim_ip)}">恢复网络</button>
    </div>`;
  }).join("");
  list.querySelectorAll("button[data-ip]").forEach(b =>
    b.addEventListener("click", () => doRestore(b.dataset.ip)));
}

/* ═══════════ 渲染：历史 / 审计 ═══════════ */
function renderSessions() {
  const tbody = $("#sessTable tbody");
  if (!state.sessions.length) {
    tbody.innerHTML = '<tr class="empty"><td colspan="4">暂无</td></tr>';
    return;
  }
  tbody.innerHTML = state.sessions.map(s => `
    <tr><td>${esc(s.started)}</td><td class="ip">${esc(s.victim_ip)}</td>
    <td>${s.mode === "island" ? "彻底断网" : "断外网"}</td>
    <td>${s.state === "运行中" ? '<span class="tag lock">运行中</span>' : esc(s.state)}</td></tr>`).join("");
}

function renderEvents() {
  const feed = $("#auditFeed");
  if (!state.events.length) { feed.innerHTML = '<div class="hint">暂无记录</div>'; return; }
  const evName = {
    scan_done: "探测完成", scan_start: "开始探测",
    isolate_start: "隔离开始", isolate_stop: "隔离结束",
    restore_done: "目标已恢复", gui_start: "控制台启动", app_start: "应用启动",
  };
  feed.innerHTML = state.events.slice().reverse().map(e => {
    const dt = Object.entries(e)
      .filter(([k]) => !["ts", "event"].includes(k))
      .map(([k, v]) => `${k}=${v}`).join("  ");
    return `<div class="audit-item">
      <span class="ts">${esc(e.ts)}</span>
      <span class="ev ${esc(e.event)}">${esc(evName[e.event] || e.event)}</span>
      <span class="dt">${esc(dt)}</span>
    </div>`;
  }).join("");
}

/* ═══════════ 设备详情抽屉（研判） ═══════════ */
function openDrawer(ip) {
  const hosts = state.scan && state.scan.last ? state.scan.last.hosts || {} : {};
  const h = hosts[ip] || {};
  $("#dwIp").textContent = ip;
  const badges = [];
  if (h.is_gateway) badges.push('<span class="tag lock">网关 🔒</span>');
  if (h.is_self) badges.push('<span class="tag lock">本机 🔒</span>');
  if (state.scan && state.scan.last && state.scan.last.segment === "routed" && !h.is_self)
    badges.push('<span class="tag far">跨网段</span>');
  $("#dwBadges").innerHTML = badges.join(" ") || '<span class="hint">普通主机</span>';

  $("#dwInfo").innerHTML = `
    <dt>设备类型</dt><dd><b style="color:var(--cyn)">${esc(inferType(h))}</b></dd>
    <dt>MAC 地址</dt><dd>${esc(h.mac) || "未知"}</dd>
    <dt>厂商</dt><dd title="${esc(h.vendor || "")}">${esc(h.vendor || "未知")}</dd>
    <dt>主机名</dt><dd>${esc(h.hostname || "未解析到")}</dd>
    <dt>开放端口</dt><dd>${(h.ports || []).map(x => `${x.port}/${esc(x.service)}`).join(" ") || (h.tcp_ping_ports || []).join(" ") || "未探测到"}</dd>
    <dt>首次发现</dt><dd>${esc(state.scan && state.scan.last ? state.scan.last.scan_time : "-")}</dd>`;

  $("#dwHits").innerHTML = (h.hits || []).length
    ? h.hits.map(x => `<span class="chip ${esc(x)}">${esc(x)}</span>`).join("")
    : '<span class="hint">无（手动输入的目标）</span>';

  $("#dwPorts").innerHTML = (h.ports || []).length
    ? h.ports.map(x => `<span class="dw-port"><b>${x.port}</b>${esc(x.service)}</span>`).join("")
    : '<span class="hint">未深度探测（可点击下方「深度探测」实时扫描）</span>';

  $("#dwProbeOut").innerHTML = '<span class="hint">点击「深度探测」实时检测目标可达性并扫描常见端口</span>';
  $("#dwIsolate").onclick = () => { closeDrawer(); openModal(ip, h.mac || null); };
  $("#drawer").classList.remove("hidden");
  $("#drawerMask").classList.remove("hidden");
}

function closeDrawer() {
  $("#drawer").classList.add("hidden");
  $("#drawerMask").classList.add("hidden");
}

async function drawerDeepProbe() {
  const ip = $("#dwIp").textContent.trim();
  if (!isIpv4(ip)) return;
  const out = $("#dwProbeOut");
  out.innerHTML = '<span class="hint">深度探测中（可达性 + 常见端口，约数秒）…</span>';
  try {
    const r = await api("/api/probe", { method: "POST", body: JSON.stringify({ ip, deep: true }) });
    if (r.error) { out.innerHTML = `<span class="hint">探测失败: ${esc(r.error)}</span>`; return; }
    const lines = [];
    lines.push(r.ping ? "● <b style='color:#8ce0b5'>ping 在线</b>"
                      : r.tcp.length ? "● <b style='color:#8ce0b5'>TCP 在线</b>"
                      : "● <b style='color:#ff9aa4'>无响应（离线或防火墙全丢）</b>");
    if (r.hostname) lines.push(`主机名: ${esc(r.hostname)}`);
    if (r.mac) lines.push(`MAC: ${esc(r.mac)} ${r.vendor ? "· " + esc(r.vendor) : ""}`);
    if (r.ports && r.ports.length) {
      out.innerHTML = lines.join("<br>") + "<br>开放端口: " +
        r.ports.map(x => `<span class="dw-port"><b>${x.port}</b>${esc(x.service)}</span>`).join("");
      // 回填端口区
      $("#dwPorts").innerHTML = r.ports.map(x => `<span class="dw-port"><b>${x.port}</b>${esc(x.service)}</span>`).join("");
    } else {
      out.innerHTML = lines.join("<br>") + "<br>常见端口均未开放";
    }
  } catch (e) {
    out.innerHTML = `<span class="hint">探测失败: ${esc(e.message)}</span>`;
  }
}

/* ═══════════ 隔离向导 ═══════════ */
function bindPresets() {
  $$(".pre").forEach(b => b.addEventListener("click", () => {
    $$(".pre").forEach(x => x.classList.remove("on"));
    b.classList.add("on");
    $("#mDur").value = b.dataset.min;
  }));
  $("#mDur").addEventListener("input", () => {
    $$(".pre").forEach(x => x.classList.toggle("on", x.dataset.min === $("#mDur").value));
  });
}

function openModal(ip, mac) {
  state.target = { ip, mac };
  const d = state.doctor;
  const hosts = state.scan && state.scan.last ? state.scan.last.hosts || {} : {};
  const h = hosts[ip] || {};
  const ifc = curIface();
  const myNet = ifc && ifc.network ? ifc.network : (d ? d.onlink : "");
  const onlink = myNet ? inSubnet(ip, myNet) : false;

  $("#mTitle").textContent = "确认隔离目标";
  $("#mTarget").innerHTML = `
    <span class="big">${esc(ip)}</span> ${esc(h.mac || mac || "")}<br>
    厂商 <b>${esc(h.vendor || "-")}</b> · 主机名 <b>${esc(h.hostname || "-")}</b><br>
    执行网卡 <b>${esc(ifc ? ifc.name : "默认出口")}</b> · 网段判定 <b>${onlink ? "本节点直连（可隔离）" : "非本网卡直连"}</b>`;

  const mp = $("#mProbe");
  mp.classList.remove("hidden");
  mp.className = "m-probe";
  mp.textContent = "可达性检测中 …";
  api("/api/probe", { method: "POST", body: JSON.stringify({ ip }) })
    .then(r => {
      if (!state.target || state.target.ip !== ip) return;
      if (r.error) { mp.textContent = "可达性检测失败"; return; }
      const via = r.ping ? "ping 通" : (r.tcp.length ? `TCP ${r.tcp[0].port} 响应` : "");
      mp.className = "m-probe " + (r.alive ? "ok" : "bad");
      mp.textContent = r.alive ? `目标在线（${via}）` : "目标无响应（可能离线或防火墙全丢）";
    })
    .catch(() => { if (state.target && state.target.ip === ip) mp.textContent = "可达性检测失败（节点无响应）"; });

  const block = $("#mBlock");
  const isAdmin = state.doctor ? state.doctor.admin : false;
  const isDry = $("#mDry").checked;
  if (!isAdmin && !isDry) {
    block.classList.remove("hidden");
    block.innerHTML = "🚫 <b>当前节点未以管理员运行，无法执行隔离</b><br>" +
      "关闭所有 AegisIR 窗口，右键「以管理员身份运行」重新启动后再试。<br>" +
      "（勾选下方「演练模式」可预览数据包，无需管理员）";
    $("#mOk").disabled = true;
  } else if (!onlink) {
    block.classList.remove("hidden");
    block.innerHTML = "目标不在所选网卡的直连网段，ARP 隔离无法穿越路由。<br>" +
      "① 确认上方「执行网卡」选择正确；② 若目标确在其他网段，请到「节点管理」按指引部署节点后接入。";
    $("#mOk").disabled = true;
  } else {
    block.classList.add("hidden");
    $("#mOk").disabled = false;
  }

  const peers = Object.values(hosts).filter(x => x.mac && !x.is_gateway && !x.is_self).length;
  const defMode = state.settings.defMode === "island" && peers >= 1 ? "island" : "offnet";
  $("#mModes").innerHTML = ["offnet", "island"].map(m => {
    const dis = m === "island" && peers < 1;
    return `<label class="mode-card ${m === defMode ? "on" : ""} ${dis ? "off" : ""}" data-mode="${m}">
      <input type="radio" name="mode" value="${m}" ${m === defMode ? "checked" : ""} ${dis ? "disabled" : ""}>
      <div class="t">${MODE_INFO[m].label}${dis ? "（需先探测出同网段邻居）" : ""}</div>
      <div class="d">${MODE_INFO[m].desc}</div>
    </label>`;
  }).join("");
  $$("#mModes .mode-card").forEach(c => c.addEventListener("click", () => {
    if (c.classList.contains("off")) return;
    $$("#mModes .mode-card").forEach(x => x.classList.remove("on"));
    c.classList.add("on");
    $("#mExclude").classList.toggle("hidden", c.dataset.mode !== "island");
  }));
  $("#mExclude").classList.toggle("hidden", defMode !== "island");

  const defDur = String(state.settings.defDur ?? 30);
  $("#mDur").value = defDur;
  $$(".pre").forEach(x => x.classList.toggle("on", x.dataset.min === defDur));
  $("#mDry").checked = false;
  $("#mDry").onchange = () => {
    // 演练模式切换时更新确认按钮状态（非管理员 + 演练 = 可用）
    if (!isAdmin) {
      $("#mOk").disabled = !$("#mDry").checked;
      if (!$("#mDry").checked) $("#mBlock").classList.remove("hidden");
      else $("#mBlock").classList.add("hidden");
    }
  };
  $("#mExcludeInput").value = "";
  $("#mInterval").value = state.settings.interval ?? 1;
  $("#mFakeMac").value = state.settings.fakeMac || "";
  $("#mNormal").classList.remove("hidden");
  $("#mPreview").classList.add("hidden");
  $("#modal").classList.remove("hidden");
}

function openBatchModal(iplist) {
  state.target = { batch: [...iplist] };
  $("#mTitle").textContent = `批量隔离 ${iplist.length} 个目标`;
  $("#mTarget").innerHTML = `<span class="big">${iplist.length} 个目标</span><br>` +
    iplist.map(ip => `· ${esc(ip)}`).join("<br>") +
    `<br>模式统一为 <b>断外网</b>（批量场景影响面最小原则）`;
  $("#mProbe").classList.add("hidden");
  $("#mBlock").classList.add("hidden");
  $("#mOk").disabled = false;
  $("#mModes").innerHTML = "";
  $("#mExclude").classList.add("hidden");
  $("#mDur").value = 30;
  $$(".pre").forEach(x => x.classList.toggle("on", x.dataset.min === "30"));
  $("#mDry").checked = false;
  $("#mNormal").classList.remove("hidden");
  $("#mPreview").classList.add("hidden");
  $("#modal").classList.remove("hidden");
}

async function confirmIsolate() {
  const t = state.target;
  if (!t) return;
  const dry = $("#mDry").checked;
  const dur = Math.max(0, parseInt($("#mDur").value || "0", 10));
  const dry_run_only = $("#mDry").checked;
  const modeEl = document.querySelector('input[name="mode"]:checked');
  const excludeVal = $("#mExcludeInput").value.trim();
  const exclude = excludeVal ? excludeVal.split(/[,,\s]+/).filter(Boolean) : [];
  const btn = $("#mOk");
  btn.disabled = true; btn.textContent = "执行中 …";
  try {
    if (t.batch) {
      let ok = 0, fail = [];
      for (const ip of t.batch) {
        try {
          const r = await api("/api/isolate", {
            method: "POST",
            body: JSON.stringify({ ip, mode: "offnet", duration_min: dur, dry_run: dry, iface: state.iface || null }),
          });
          if (r.error) fail.push(ip); else ok++;
        } catch (e) { fail.push(ip); }
      }
      $("#modal").classList.add("hidden");
      toast(`批量隔离完成：成功 ${ok} 台${fail.length ? `，失败 ${fail.length} 台（${fail.join(" ")}）` : ""}`,
        fail.length ? "" : "ok");
      switchView("iso");
      pollOnce();
      return;
    }
    const r = await api("/api/isolate", {
      method: "POST",
      body: JSON.stringify({
        ip: t.ip, mode: modeEl ? modeEl.value : "offnet",
        duration_min: dur, dry_run: dry,
        victim_mac: t.mac || null,
        iface: state.iface || null,
        exclude,
        interval: Math.min(5, Math.max(0.3, parseFloat($("#mInterval").value || "1") || 1)),
        fake_mac: ($("#mFakeMac").value.trim()) || undefined,
      }),
    });
    if (r.error) { toast(r.error, "err"); return; }
    if (r.dry_run) {
      $("#mNormal").classList.add("hidden");
      $("#mPreview").classList.remove("hidden");
      $("#mPvInfo").textContent = `演练模式：目标 ${t.ip} · 未发送任何数据包。每轮将发送：`;
      $("#mPvBody").textContent = (r.preview || []).join("\n");
      return;
    }
    $("#modal").classList.add("hidden");
    toast(`已开始隔离 ${t.ip}`, "ok");
    switchView("iso");
    pollOnce();
  } catch (e) {
    toast("请求失败: " + e.message, "err");
  } finally {
    btn.disabled = false; btn.textContent = "确认隔离";
  }
}

async function doRestore(ip) {
  try {
    const r = await api("/api/restore", { method: "POST", body: JSON.stringify({ ip }) });
    if (r.error) return toast(r.error, "err");
    if (r.online === true) toast(`已恢复，目标 ${ip} 重新在线 ✓`, "ok");
    else if (r.online === false) toast(`恢复指令已下发；目标 ${ip} 暂未响应 ping（防火墙可能挡 ICMP，属正常）`, "");
    else toast(`已下发恢复指令，${ip} 将在数秒内恢复网络`, "ok");
    pollOnce();
  } catch (e) {
    toast("请求失败: " + e.message, "err");
  }
}

/* ═══════════ 轮询 ═══════════ */
let tick = 0;
let _lastScanTime = "";  // 上次渲染的 scan_time，防止轮询重建表格销毁勾选状态

async function pollOnce() {
  try {
    const [scan, iso, sess, ev] = await Promise.all([
      api("/api/scan"), api("/api/isolate"), api("/api/sessions"), api("/api/events"),
    ]);

    // 只在扫描数据真正变化时才重绘主机表（scan_time 或进度状态变了）
    const scanTime = scan.last ? scan.last.scan_time : "";
    const scanChanged = scanTime !== _lastScanTime || (scan.running !== (state.scan && state.scan.running));
    state.scan = scan;
    state.active = iso.active || [];
    state.sessions = sess.sessions || [];
    state.events = ev.events || [];

    if (tick++ % 5 === 0) {
      const [doc, ifs] = await Promise.all([api("/api/doctor"), api("/api/interfaces")]);
      state.doctor = doc;
      const list = ifs.interfaces || [];
      if (JSON.stringify(list) !== JSON.stringify(state.interfaces)) {
        state.interfaces = list;
        renderInterfaces();
      }
      renderDoctor();
    }

    // 扫描进度条始终更新（轻量，不重建表格）
    const p = $("#scanProgress");
    if (scan.running) {
      p.classList.remove("hidden");
      const [done, total] = scan.progress || [0, 0];
      p.querySelector(".txt").textContent =
        `${scan.stage || "探测中"} ${total ? Math.round(done / total * 100) + "%" : ""} · 请稍候`;
      $("#scanBtn").disabled = true;
    } else {
      p.classList.add("hidden");
      $("#scanBtn").disabled = false;
    }

    // 只在扫描结果变化时才重建主机表格
    if (scanChanged) {
      _lastScanTime = scanTime;
      renderHosts(scan.last);
    }

    renderActive(); renderSessions(); renderEvents();
  } catch (e) {
    /* 节点离线等场景静默重试 */
  }
}
function refreshAll() { tick = 0; pollOnce(); }

/* ═══════════ 初始化 ═══════════ */
function init() {
  $$(".nav-item").forEach(b => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#nodeAdd").addEventListener("click", () => {
    $("#nmUrl").value = ""; $("#nmToken").value = ""; $("#nmName").value = "";
    $("#nodeModal").classList.remove("hidden");
    setTimeout(() => $("#nmUrl").focus(), 50);
  });
  $("#nmCancel").addEventListener("click", () => $("#nodeModal").classList.add("hidden"));
  $("#nmOk").addEventListener("click", addNodeSubmit);
  $("#nodeModal").addEventListener("click", (e) => {
    if (e.target === $("#nodeModal")) $("#nodeModal").classList.add("hidden");
  });
  $("#nodeSelect").addEventListener("change", async (e) => {
    if (e.target.value === "") { state.cur = null; renderNodeSelect(); renderNodeList(); refreshAll(); }
    else await switchNodeByIndex(+e.target.value);
  });

  $("#ifaceSel").addEventListener("change", (e) => { state.iface = e.target.value; prefillNet(); });
  $("#engineSel").addEventListener("change", updateEngineUI);
  $("#optPassive").addEventListener("change", (e) => {
    $("#passiveWarn").classList.toggle("hidden", !e.target.checked);
    if (e.target.checked) {
      toast("零流量被动模式：只读 ARP 缓存，不发送任何探测包。仅能发现本机最近通信过的设备，建议仅用于需要完全静默的场景", "");
    }
  });
  $$("#rawMethods .mchip").forEach(c => c.addEventListener("click", (e) => {
    e.preventDefault();
    c.classList.toggle("on");
    c.querySelector("input").checked = c.classList.contains("on");
  }));
  $("#scanBtn").addEventListener("click", async () => {
    const net = $("#netInput").value.trim();
    if (!net) return toast("请输入目标，如 192.168.1.0/24 或 192.168.1.10-60", "err");
    const engine = $("#engineSel").value;
    let methods = [];
    if ($("#optPassive").checked) methods.push("passive");
    $$("#rawMethods .mchip input:checked").forEach(i => methods.push(i.value));
    try {
      const r = await api("/api/scan", {
        method: "POST",
        body: JSON.stringify({
          net, ports: $("#optPorts").checked,
          iface: state.iface || null,
          engine, methods,
        }),
      });
      if (r.error) return toast(r.error, "err");
      if ($("#optPassive").checked) {
        toast("被动模式启动中（只读 ARP 缓存，可能遗漏设备）…", "");
      } else {
        toast("探测已开始", "ok");
      }
      pollOnce();
      // 被动扫描结束后如果结果太少，自动建议升级到主动探测
      if ($("#optPassive").checked) {
        const checkInterval = setInterval(async () => {
          const s = await api("/api/scan").catch(() => null);
          if (!s || s.running) return;
          clearInterval(checkInterval);
          const count = Object.keys(s.last?.hosts || {}).length;
          if (count < 5) {
            toast(`被动模式仅发现 ${count} 台设备（可能遗漏大量主机）。取消勾选「零流量被动」后重新探测可发现更多设备`, "err");
          }
        }, 2000);
        setTimeout(() => clearInterval(checkInterval), 60000); // 最长等60秒
      }
    } catch (e) { toast("请求失败: " + e.message, "err"); }
  });

  $("#filterInput").addEventListener("input", (e) => {
    state.filter = e.target.value;
    if (state.scan) renderHosts(state.scan.last, true);
  });
  $("#csvBtn").addEventListener("click", exportCsv);
  $("#selAll").addEventListener("change", (e) => {
    const checked = e.target.checked;
    $$("#hostsTable input[data-bip]").forEach(b => {
      b.checked = checked;
      const ip = b.dataset.bip;
      if (checked) state.checked.add(ip); else state.checked.delete(ip);
      b.closest("tr").classList.toggle("marked", checked);
    });
    updateBatchBtn();
  });
  $("#batchBtn").addEventListener("click", () => {
    if (state.checked.size) openBatchModal([...state.checked]);
  });

  const manualGo = (inputSel) => () => {
    const ip = $(inputSel).value.trim();
    if (!isIpv4(ip)) return toast("IP 格式不正确", "err");
    openModal(ip, null);
  };
  $("#manualBtn").addEventListener("click", manualGo("#manualIp"));
  $("#manualBtn2").addEventListener("click", manualGo("#manualIp2"));

  $("#mCancel").addEventListener("click", () => $("#modal").classList.add("hidden"));
  $("#mClose").addEventListener("click", () => $("#modal").classList.add("hidden"));
  $("#mOk").addEventListener("click", confirmIsolate);
  $("#modal").addEventListener("click", (e) => {
    if (e.target === $("#modal")) $("#modal").classList.add("hidden");
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { $("#modal").classList.add("hidden"); $("#nodeModal").classList.add("hidden"); closeDrawer(); }
  });

  // 设备详情抽屉
  $("#dwClose").addEventListener("click", closeDrawer);
  $("#drawerMask").addEventListener("click", closeDrawer);
  $("#dwProbe").addEventListener("click", drawerDeepProbe);

  // 设置视图
  $("#setMode").value = state.settings.defMode || "offnet";
  $("#setDur").value = state.settings.defDur ?? 30;
  $("#setInterval").value = state.settings.interval ?? 1;
  $("#setFakeMac").value = state.settings.fakeMac || "";
  $("#setSave").addEventListener("click", () => {
    const mac = $("#setFakeMac").value.trim();
    if (mac && !/^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(mac))
      return toast("假 MAC 格式应为 aa:bb:cc:dd:ee:ff", "err");
    state.settings = {
      defMode: $("#setMode").value,
      defDur: Math.max(0, parseInt($("#setDur").value || "30", 10) || 0),
      interval: Math.min(5, Math.max(0.3, parseFloat($("#setInterval").value || "1") || 1)),
      fakeMac: mac,
    };
    saveSettings();
    toast("设置已保存（本地持久化，不影响其他操作员）", "ok");
  });

  bindPresets();
  $("#copySh").addEventListener("click", async () => {
    const ok = await copyText($("#cmdSh").textContent);
    toast(ok ? "Linux 部署命令已复制，贴到目标机器终端执行即可" : "复制失败，请手动选择复制", ok ? "ok" : "err");
  });
  $("#copyPs").addEventListener("click", async () => {
    const ok = await copyText($("#cmdPs").textContent);
    toast(ok ? "Windows 部署命令已复制，请在目标机管理员 PowerShell 执行" : "复制失败，请手动选择复制", ok ? "ok" : "err");
  });
  $("#tokenRegen").addEventListener("click", () => {
    state.deployToken = genToken();
    renderDeploy();
    toast("已生成新令牌，请使用新命令部署", "ok");
  });

  renderDeploy();
  renderNodeList();
  refreshAll();
  setInterval(pollOnce, 2000);
  setInterval(checkNodes, 15000);
  checkNodes();
}

async function checkNodes() {
  await Promise.all(state.nodes.map(async n => {
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), 3000);
      const r = await fetch(n.url + "/api/doctor", {
        headers: n.token ? { "X-Aegis-Token": n.token } : {},
        signal: ctl.signal,
      });
      clearTimeout(timer);
      state.nodeHealth[n.url] = r.ok;
    } catch (e) {
      state.nodeHealth[n.url] = false;
    }
  }));
  if (state.view === "nodes") renderNodeList();
}

init();
