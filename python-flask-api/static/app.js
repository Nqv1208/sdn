const summaryCardsEl = document.getElementById("summary-cards");
const switchTableBody = document.querySelector("#switch-table tbody");
const hostTableBody = document.querySelector("#host-table tbody");
const blacklistEl = document.getElementById("blacklist");

async function fetchJSON(url) {
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }
  return resp.json();
}

function formatDate(ts) {
  if (!ts) return "N/A";
  return new Date(ts * 1000).toLocaleString();
}

async function refresh() {
  try {
    const summary = await fetchJSON("/api/summary");
    const switches = await fetchJSON("/api/switches");
    const hosts = await fetchJSON("/api/hosts");
    const anomalies = await fetchJSON("/api/anomalies");

    renderSummary(summary);
    renderSwitches(switches);
    renderHosts(hosts, anomalies);
    renderBlacklist(summary?.threats?.blacklist || []);
  } catch (err) {
    console.error("Không thể tải dashboard", err);
  }
}

function renderSummary(summary) {
  const net = summary.network || {};
  const stats = summary.stats || {};
  const cards = [
    { label: "Switch", value: net.switch_count || 0 },
    { label: "Hosts", value: net.host_count || 0 },
    { label: "Attack phát hiện", value: stats.total_attacks_detected || 0 },
    { label: "Đã block", value: stats.blocked_ips?.length || 0 },
    { label: "Cập nhật", value: formatDate(summary.updated_at) },
  ];

  summaryCardsEl.innerHTML = cards
    .map(
      (card) => `
      <div class="card">
        <h3>${card.label}</h3>
        <span>${card.value}</span>
      </div>
    `
    )
    .join("");
}

function renderSwitches(rows) {
  switchTableBody.innerHTML = rows
    .map(
      (sw) => `
      <tr>
        <td>${sw.dpid}</td>
        <td>${sw.flow_count}</td>
        <td>${sw.port_count}</td>
      </tr>
    `
    )
    .join("");
}

function renderHosts(hosts = {}, anomalies = {}) {
  const rows = Object.keys(hosts).map((ip) => ({
    ip,
    ...hosts[ip],
    anomaly: anomalies[ip] || 0,
  }));

  hostTableBody.innerHTML = rows
    .map(
      (host) => `
      <tr>
        <td>${host.ip}</td>
        <td>${host.packet_rate?.toFixed(2) || 0}</td>
        <td>${host.byte_rate?.toFixed(2) || 0}</td>
        <td>${host.anomaly?.toFixed(2)}</td>
        <td>${formatDate(host.last_seen)}</td>
      </tr>
    `
    )
    .join("");
}

function renderBlacklist(list) {
  blacklistEl.innerHTML = list.map((ip) => `<li>${ip}</li>`).join("");
}

async function submitCommand(endpoint, formEl) {
  const formData = new FormData(formEl);
  const payload = Object.fromEntries(formData.entries());
  try {
    await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    formEl.reset();
    refresh();
  } catch (err) {
    console.error("Command error", err);
  }
}

document.getElementById("block-form").addEventListener("submit", (e) => {
  e.preventDefault();
  submitCommand("/api/commands/block", e.target);
});

document.getElementById("unblock-form").addEventListener("submit", (e) => {
  e.preventDefault();
  submitCommand("/api/commands/unblock", e.target);
});

refresh();
setInterval(refresh, 5000);

