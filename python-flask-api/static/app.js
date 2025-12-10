const summaryCardsEl = document.getElementById("summary-cards");
const switchTableBody = document.querySelector("#switch-table tbody");
const hostTableBody = document.querySelector("#host-table tbody");
const blacklistEl = document.getElementById("blacklist");
const qosTableBody = document.getElementById("qos-table-body");

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
    const qos = await fetchJSON("/api/qos");

    renderSummary(summary);
    renderSwitches(switches);
    renderHosts(hosts, anomalies);
    renderBlacklist(summary?.threats?.blacklist || []);
    renderQoS(qos);
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

  // Sort: blacklisted IPs first, then by packet_rate
  rows.sort((a, b) => {
    const aBlocked = a.is_blacklisted || false;
    const bBlocked = b.is_blacklisted || false;
    if (aBlocked && !bBlocked) return -1;
    if (!aBlocked && bBlocked) return 1;
    return (b.packet_rate || 0) - (a.packet_rate || 0);
  });

  hostTableBody.innerHTML = rows
    .map(
      (host) => {
        const isBlocked = host.is_blacklisted || false;
        const rowClass = isBlocked ? 'blocked-host' : '';
        const blockedBadge = isBlocked ? ' <span class="badge blocked">BLOCKED</span>' : '';
        return `
      <tr class="${rowClass}">
        <td>${host.ip}${blockedBadge}</td>
        <td>${host.packet_rate?.toFixed(2) || 0}</td>
        <td>${host.byte_rate?.toFixed(2) || 0}</td>
        <td>${host.anomaly?.toFixed(2)}</td>
        <td>${formatDate(host.last_seen)}</td>
      </tr>
    `;
      }
    )
    .join("");
}

function renderBlacklist(list) {
  blacklistEl.innerHTML = list.map((ip) => `<li>${ip}</li>`).join("");
}

function renderQoS(qos = {}) {
  const rows = Object.keys(qos).map((ip) => ({
    ip,
    ...qos[ip],
  }));

  if (rows.length === 0) {
    qosTableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 2rem;">Chưa có cấu hình QoS</td></tr>';
    return;
  }

  // Check if mobile view (screen width < 768px)
  // Use matchMedia for better detection
  const isMobile = window.matchMedia("(max-width: 767px)").matches;
  
  if (isMobile) {
    // Mobile-friendly card layout
    qosTableBody.innerHTML = rows
      .map(
        (q) => `
        <tr class="qos-mobile-row">
          <td colspan="5">
            <div class="qos-mobile-card">
              <div class="qos-mobile-header">
                <strong>${q.ip}</strong>
                <button class="remove-qos-btn" data-ip="${q.ip}">Remove</button>
              </div>
              <div class="qos-mobile-details">
                <div><span class="qos-label">Rate:</span> ${q.rate_kbps} kbps</div>
                <div><span class="qos-label">Burst:</span> ${q.burst_kb || "N/A"} KB</div>
                <div><span class="qos-label">Meter ID:</span> ${q.meter_id}</div>
              </div>
            </div>
          </td>
        </tr>
      `
      )
      .join("");
  } else {
    // Desktop table layout
    qosTableBody.innerHTML = rows
      .map(
        (q) => `
        <tr>
          <td>${q.ip}</td>
          <td>${q.rate_kbps}</td>
          <td>${q.burst_kb || "N/A"}</td>
          <td>${q.meter_id}</td>
          <td>
            <button class="remove-qos-btn" data-ip="${q.ip}">Remove</button>
          </td>
        </tr>
      `
      )
      .join("");
  }

  // Attach event listeners to remove buttons
  document.querySelectorAll(".remove-qos-btn").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const ip = e.target.getAttribute("data-ip");
      if (!confirm(`Bạn có chắc muốn xóa QoS cho ${ip}?`)) {
        return;
      }
      try {
        await fetch("/api/commands/qos/remove", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip }),
        });
        refresh();
      } catch (err) {
        console.error("Remove QoS error", err);
        alert("Lỗi khi xóa QoS: " + err.message);
      }
    });
  });
}

// Re-render QoS table on window resize
let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    // Re-fetch and render QoS to update layout
    fetchJSON("/api/qos").then((qos) => renderQoS(qos));
  }, 250);
});

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

document.getElementById("qos-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const formData = new FormData(e.target);
  const payload = {
    ip: formData.get("ip"),
    rate_kbps: parseInt(formData.get("rate_kbps")),
  };
  const burst_kb = formData.get("burst_kb");
  if (burst_kb) {
    payload.burst_kb = parseInt(burst_kb);
  }
  try {
    await fetch("/api/commands/qos/set", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    e.target.reset();
    refresh();
  } catch (err) {
    console.error("QoS set error", err);
    alert("Lỗi khi cấu hình QoS: " + err.message);
  }
});

refresh();
setInterval(refresh, 5000);

