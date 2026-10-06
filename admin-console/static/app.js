let authHeader = null;
let actorName = "admin";
let assetsCache = [];
let editingIp = null;

function showToast(text, isError) {
  const t = document.getElementById("toast");
  t.textContent = text;
  t.className = "toast show" + (isError ? " error" : "");
  setTimeout(() => { t.className = "toast"; }, 4500);
}

async function api(path, options) {
  options = options || {};
  options.headers = Object.assign({}, options.headers, {
    "Authorization": authHeader,
    "Content-Type": "application/json",
  });
  const res = await fetch(path, options);
  if (res.status === 401) {
    showToast("Login failed - check admin username/password.", true);
    throw new Error("unauthorized");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    showToast(data.detail || `Request failed (${res.status})`, true);
    throw new Error(data.detail || "request failed");
  }
  return data;
}

document.getElementById("login-btn").addEventListener("click", async () => {
  const user = document.getElementById("login-user").value.trim();
  const pass = document.getElementById("login-pass").value;
  actorName = document.getElementById("actor-name").value.trim() || "admin";
  authHeader = "Basic " + btoa(`${user}:${pass}`);
  const statusEl = document.getElementById("login-status");
  try {
    await loadAgents();
    await loadAssets();
    await loadAlerts();
    statusEl.textContent = "Connected";
    statusEl.style.color = "#34D399";
  } catch (e) {
    statusEl.textContent = "Not connected";
    statusEl.style.color = "#EF4444";
  }
});

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

document.getElementById("refresh-assets").addEventListener("click", loadAssets);

// --- Manually add an asset (e.g. a VM Zeek hasn't seen traffic from yet) ---
const addAssetForm = document.getElementById("add-asset-form");
document.getElementById("add-asset-btn").addEventListener("click", () => {
  addAssetForm.style.display = addAssetForm.style.display === "none" ? "flex" : "none";
});
document.getElementById("cancel-new-asset").addEventListener("click", () => {
  addAssetForm.style.display = "none";
});
document.getElementById("save-new-asset").addEventListener("click", async () => {
  const ip = document.getElementById("new-asset-ip").value.trim();
  if (!ip) { showToast("Enter an IP address first.", true); return; }
  try {
    await api("/api/assets/add", {
      method: "POST",
      body: JSON.stringify({
        ip,
        zone: document.getElementById("new-asset-zone").value,
        owner: document.getElementById("new-asset-owner").value,
        criticality: document.getElementById("new-asset-crit").value,
        tags: document.getElementById("new-asset-tags").value,
        notes: "",
        actor: actorName,
      }),
    });
    showToast(`Added ${ip}`);
    ["new-asset-ip", "new-asset-owner", "new-asset-tags"].forEach((id) => { document.getElementById(id).value = ""; });
    addAssetForm.style.display = "none";
    await loadAssets();
  } catch (e) { /* toast already shown */ }
});
document.getElementById("refresh-alerts").addEventListener("click", loadAlerts);
document.getElementById("refresh-agents").addEventListener("click", loadAgents);
document.getElementById("deploy-agent-btn").addEventListener("click", openDeployModal);

function zoneBadge(zone) {
  const cls = zone === "OT" ? "badge-ot" : zone === "IT" ? "badge-it" : "badge-none";
  return `<span class="badge ${cls}">${zone || "-"}</span>`;
}
function criticalityBadge(c) {
  if (!c) return `<span class="badge badge-none">unset</span>`;
  const cls = c === "critical" ? "badge-critical" : c === "high" ? "badge-high" : c === "medium" ? "badge-medium" : "badge-none";
  return `<span class="badge ${cls}">${c}</span>`;
}
function policyBadge(p) {
  const cls = "badge-" + (p || "none");
  return `<span class="badge ${cls}">${p || "none"}</span>`;
}
function statusBadge(s) {
  const label = { open: "Open", allow: "Allowed", block: "Blocked", investigate: "Investigating" }[s] || "Open";
  const cls = "badge-" + label.toLowerCase();
  return `<span class="badge ${cls}">${label}</span>`;
}
function agentStatusBadge(lastCheckin) {
  const active = (Date.now() / 1000 - lastCheckin) < 90;
  return active ? `<span class="badge badge-active">active</span>` : `<span class="badge badge-disconnected">disconnected</span>`;
}
function fmtTs(ts) {
  if (!ts) return "-";
  return new Date(ts * 1000).toLocaleString();
}

// ---------------------------------------------------------------------
// Pure-CSS donut chart (conic-gradient) - no chart library dependency
// ---------------------------------------------------------------------
function renderDonut(container, title, segments) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  let acc = 0;
  const stops = segments.map((s) => {
    const start = (acc / total) * 100;
    acc += s.value;
    const end = (acc / total) * 100;
    return `${s.color} ${start}% ${end}%`;
  }).join(", ");
  const gradient = total > 0 ? `conic-gradient(${stops})` : "#232327";

  const legend = segments.map((s) =>
    `<div><span class="legend-dot" style="background:${s.color};"></span>${s.label} (${s.value})</div>`
  ).join("");

  container.innerHTML = `
    <div>
      <h4>${title}</h4>
      <div style="display:flex; align-items:center; gap:16px;">
        <div class="donut" style="background:${gradient};"></div>
        <div class="stat-legend">${legend}</div>
      </div>
    </div>`;
}

async function loadAgents() {
  const rows = await api("/api/agents");
  renderAgents(rows);
}

function renderAgents(rows) {
  document.getElementById("agents-count").textContent = `Agents (${rows.length})`;

  const now = Date.now() / 1000;
  const activeCount = rows.filter(r => (now - r.last_checkin) < 90).length;
  const statsRow = document.getElementById("agent-stats");
  statsRow.innerHTML = "";

  const statusCard = document.createElement("div"); statusCard.className = "stat-card";
  const osCard = document.createElement("div"); osCard.className = "stat-card";
  const groupCard = document.createElement("div"); groupCard.className = "stat-card";
  statsRow.append(statusCard, osCard, groupCard);

  renderDonut(statusCard, "Agents by status", [
    { label: "Active", value: activeCount, color: "#34D399" },
    { label: "Disconnected", value: rows.length - activeCount, color: "#EF4444" },
  ]);

  const osCounts = {};
  rows.forEach(r => { osCounts[r.os || "unknown"] = (osCounts[r.os || "unknown"] || 0) + 1; });
  const osColors = ["#22D3EE", "#A78BFA", "#F59E0B", "#34D399", "#EF4444"];
  renderDonut(osCard, "Top OS", Object.entries(osCounts).slice(0, 5).map(([label, value], i) =>
    ({ label, value, color: osColors[i % osColors.length] })));

  const groupCounts = {};
  rows.forEach(r => { groupCounts[r.agent_group || "default"] = (groupCounts[r.agent_group || "default"] || 0) + 1; });
  renderDonut(groupCard, "Top groups", Object.entries(groupCounts).slice(0, 5).map(([label, value], i) =>
    ({ label, value, color: osColors[i % osColors.length] })));

  const tbody = document.querySelector("#agents-table tbody");
  tbody.innerHTML = "";
  rows.forEach((a) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${a.agent_id}</td>
      <td>${a.hostname}</td>
      <td>${a.ip}</td>
      <td>${a.os}</td>
      <td>${a.agent_group}</td>
      <td>${a.version}</td>
      <td>${fmtTs(a.last_checkin)}</td>
      <td>${agentStatusBadge(a.last_checkin)}</td>`;
    tbody.appendChild(tr);
  });
}

async function openDeployModal() {
  try {
    const info = await api("/api/agents/install-info");
    const serverUrl = window.location.origin;
    const cmd =
`pip install scapy requests
python sniffer_agent.py --server ${serverUrl} --api-key ${info.agent_api_key} --group default`;
    document.getElementById("deploy-command").textContent = cmd;
    document.getElementById("deploy-modal").classList.add("show");
  } catch (e) { /* toast already shown */ }
}

async function loadAssets() {
  const rows = await api("/api/assets");
  assetsCache = rows;
  renderAssets();
}

function renderAssets() {
  const tbody = document.querySelector("#assets-table tbody");
  tbody.innerHTML = "";
  assetsCache.forEach((a) => {
    const tr = document.createElement("tr");
    if (editingIp === a.ip) {
      tr.innerHTML = `
        <td>${assetIpCell(a)}</td>
        <td>${zoneBadge(a.zone)}</td>
        <td>${fmtTs(a.first_seen)}</td>
        <td>${fmtTs(a.last_seen)}</td>
        <td><input class="small-input" id="edit-owner" value="${a.owner || ""}"></td>
        <td>
          <select id="edit-criticality" class="small-input">
            ${["", "low", "medium", "high", "critical"].map(c =>
              `<option value="${c}" ${c === a.criticality ? "selected" : ""}>${c || "unset"}</option>`).join("")}
          </select>
        </td>
        <td><input class="small-input" id="edit-tags" value="${a.tags || ""}"></td>
        <td>${policyBadge(a.policy)}</td>
        <td class="row-actions">
          <button class="btn-allow" onclick="saveAssetAdmin('${a.ip}')">Save</button>
          <button onclick="cancelEditAsset()">Cancel</button>
        </td>`;
    } else {
      tr.innerHTML = `
        <td>${assetIpCell(a)}</td>
        <td>${zoneBadge(a.zone)}</td>
        <td>${fmtTs(a.first_seen)}</td>
        <td>${fmtTs(a.last_seen)}</td>
        <td>${a.owner || "-"}</td>
        <td>${criticalityBadge(a.criticality)}</td>
        <td>${a.tags || "-"}</td>
        <td>${policyBadge(a.policy)}</td>
        <td class="row-actions">
          <button class="btn-edit" onclick="startEditAsset('${a.ip}')">Edit</button>
          <button class="btn-allow" onclick="setPolicy('${a.ip}', 'whitelist', '${a.criticality}')">Whitelist</button>
          <button class="btn-block" onclick="setPolicy('${a.ip}', 'blacklist', '${a.criticality}')">Blacklist</button>
          <button class="btn-investigate" onclick="setPolicy('${a.ip}', 'quarantine', '${a.criticality}')">Quarantine</button>
          ${a.policy !== "none" ? `<button onclick="setPolicy('${a.ip}', 'none', '${a.criticality}')">Clear</button>` : ""}
        </td>`;
    }
    tbody.appendChild(tr);
  });
}

function assetIpCell(a) {
  const badge = a.agent_hostname
    ? ` <span class="badge badge-active">agent: ${a.agent_hostname}</span>` : "";
  return `${a.ip}${badge}`;
}

function startEditAsset(ip) { editingIp = ip; renderAssets(); }
function cancelEditAsset() { editingIp = null; renderAssets(); }

async function saveAssetAdmin(ip) {
  const owner = document.getElementById("edit-owner").value;
  const criticality = document.getElementById("edit-criticality").value;
  const tags = document.getElementById("edit-tags").value;
  try {
    await api("/api/assets/admin", {
      method: "POST",
      body: JSON.stringify({ ip, owner, criticality, tags, notes: "", actor: actorName }),
    });
    showToast(`Updated ${ip}`);
    editingIp = null;
    await loadAssets();
  } catch (e) { /* toast already shown */ }
}

async function setPolicy(ip, policy, criticality) {
  const verbs = { blacklist: "BLACKLIST (block all traffic)", quarantine: "QUARANTINE (isolate from network)",
                  whitelist: "WHITELIST", none: "clear the policy on" };
  if (!confirm(`Are you sure you want to ${verbs[policy] || policy} ${ip}?`)) return;

  let confirmCritical = false;
  if ((policy === "blacklist" || policy === "quarantine") && criticality === "critical") {
    const typed = prompt(
      `${ip} is tagged CRITICAL. This asset matters - a mistake here has real consequences.\n` +
      `Type CONFIRM (all caps) to proceed with ${policy.toUpperCase()}:`
    );
    if (typed !== "CONFIRM") { showToast("Cancelled - confirmation text did not match.", true); return; }
    confirmCritical = true;
  }

  try {
    const result = await api("/api/assets/policy", {
      method: "POST",
      body: JSON.stringify({ ip, policy, actor: actorName, notes: "", confirm_critical: confirmCritical }),
    });
    showToast(`${ip}: ${result.detail}`, result.enforcement_status === "stubbed");
    await loadAssets();
  } catch (e) { /* toast already shown */ }
}

async function loadAlerts() {
  const rows = await api("/api/alerts?limit=200");
  renderAlerts(rows);
}

function renderAlerts(rows) {
  const tbody = document.querySelector("#alerts-table tbody");
  tbody.innerHTML = "";
  rows.forEach((a) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${fmtTs(a.ts)}</td>
      <td>${a.note_type}</td>
      <td>${a.message}</td>
      <td>${a.src_h}</td>
      <td>${a.dst_h}</td>
      <td>${a.severity}</td>
      <td>${zoneBadge(a.zone)}</td>
      <td>${a.source || "zeek-sensor"}</td>
      <td>${statusBadge(a.status)}</td>
      <td class="row-actions">
        <button class="btn-allow" onclick='alertAction(${JSON.stringify(a.id)}, "${a.src_h}", "${a.dst_h}", "allow")'>Allow</button>
        <button class="btn-block" onclick='alertAction(${JSON.stringify(a.id)}, "${a.src_h}", "${a.dst_h}", "block")'>Block</button>
        <button class="btn-investigate" onclick='alertAction(${JSON.stringify(a.id)}, "${a.src_h}", "${a.dst_h}", "investigate")'>Investigate</button>
      </td>`;
    tbody.appendChild(tr);
  });
}

async function alertAction(alertId, srcH, dstH, action) {
  if (action === "block" && !confirm(`Block traffic between ${srcH} and ${dstH}?`)) return;
  try {
    const result = await api("/api/alerts/action", {
      method: "POST",
      body: JSON.stringify({ alert_id: alertId, src_h: srcH, dst_h: dstH, action, actor: actorName, notes: "" }),
    });
    showToast(result.detail, result.enforcement_status === "stubbed");
    await loadAlerts();
  } catch (e) { /* toast already shown */ }
}
