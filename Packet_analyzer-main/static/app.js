/**
 * DPI Engine Dashboard — Frontend Logic
 * Handles file upload, API communication, chart rendering, and DOM updates.
 */

// ============================================================
// DOM References
// ============================================================
const uploadZone = document.getElementById("upload-zone");
const pcapInput = document.getElementById("pcap-input");
const fileInfo = document.getElementById("file-info");
const fileName = document.getElementById("file-name");
const fileSize = document.getElementById("file-size");
const btnAnalyze = document.getElementById("btn-analyze");
const loadingOverlay = document.getElementById("loading-overlay");
const resultsSection = document.getElementById("results-section");
const emptyState = document.getElementById("empty-state");
const errorBanner = document.getElementById("error-banner");
const errorText = document.getElementById("error-text");
const domainSearch = document.getElementById("domain-search");

// Inputs
const blockIpsInput = document.getElementById("block-ips");
const blockAppsInput = document.getElementById("block-apps");
const blockDomainsInput = document.getElementById("block-domains");

// Chart instances
let chartProtocol = null;
let chartApps = null;
let chartLB = null;
let chartFP = null;

// Current selected file
let selectedFile = null;

// ============================================================
// Chart.js Global Config
// ============================================================
Chart.defaults.color = "#94a3b8";
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.plugins.legend.labels.padding = 16;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.legend.labels.pointStyleWidth = 10;

// ============================================================
// Color Palette for Charts
// ============================================================
const CHART_COLORS = [
  "#00d4ff", // cyan
  "#7c3aed", // purple
  "#f43f5e", // pink
  "#10b981", // emerald
  "#f59e0b", // amber
  "#3b82f6", // blue
  "#ec4899", // hot pink
  "#14b8a6", // teal
  "#8b5cf6", // violet
  "#ef4444", // red
  "#06b6d4", // sky
  "#84cc16", // lime
  "#f97316", // orange
  "#6366f1", // indigo
  "#a855f7", // fuchsia
  "#22d3ee", // light cyan
  "#e879f9", // magenta
  "#fbbf24", // yellow
];

function getColor(index) {
  return CHART_COLORS[index % CHART_COLORS.length];
}

function getColorAlpha(index, alpha) {
  const hex = CHART_COLORS[index % CHART_COLORS.length];
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

// ============================================================
// Upload Handlers
// ============================================================

// Click to browse
uploadZone.addEventListener("click", () => pcapInput.click());

// File selected via input
pcapInput.addEventListener("change", (e) => {
  if (e.target.files.length > 0) {
    handleFileSelected(e.target.files[0]);
  }
});

// Drag & drop
uploadZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  uploadZone.classList.add("drag-over");
});

uploadZone.addEventListener("dragleave", () => {
  uploadZone.classList.remove("drag-over");
});

uploadZone.addEventListener("drop", (e) => {
  e.preventDefault();
  uploadZone.classList.remove("drag-over");
  if (e.dataTransfer.files.length > 0) {
    handleFileSelected(e.dataTransfer.files[0]);
  }
});

function handleFileSelected(file) {
  if (!file.name.toLowerCase().endsWith(".pcap")) {
    showError("Please select a .pcap file");
    return;
  }
  selectedFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  fileInfo.classList.add("visible");
  btnAnalyze.disabled = false;
  hideError();
}

// ============================================================
// Analyze Button
// ============================================================
btnAnalyze.addEventListener("click", async () => {
  if (!selectedFile) return;

  // Show loading
  loadingOverlay.classList.add("active");
  resultsSection.classList.remove("visible");
  emptyState.style.display = "none";
  hideError();
  btnAnalyze.disabled = true;

  // Build form data
  const formData = new FormData();
  formData.append("pcap_file", selectedFile);

  // Parse comma-separated blocking rules
  const blockIps = blockIpsInput.value.split(",").map((s) => s.trim()).filter(Boolean);
  const blockApps = blockAppsInput.value.split(",").map((s) => s.trim()).filter(Boolean);
  const blockDomains = blockDomainsInput.value.split(",").map((s) => s.trim()).filter(Boolean);

  blockIps.forEach((ip) => formData.append("block_ips", ip));
  blockApps.forEach((app) => formData.append("block_apps", app));
  blockDomains.forEach((dom) => formData.append("block_domains", dom));

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "Analysis failed");
    }

    renderResults(data);
  } catch (err) {
    showError(err.message || "Failed to connect to server");
    emptyState.style.display = "block";
  } finally {
    loadingOverlay.classList.remove("active");
    btnAnalyze.disabled = false;
  }
});

// ============================================================
// Render Results
// ============================================================
function renderResults(data) {
  // Show results section
  resultsSection.classList.add("visible");
  emptyState.style.display = "none";

  // --- Engine Config ---
  document.getElementById("cfg-lbs").textContent = data.engine_config.num_lbs;
  document.getElementById("cfg-fps-per-lb").textContent = data.engine_config.fps_per_lb;
  document.getElementById("cfg-total-fps").textContent = data.engine_config.total_fps;

  // --- Blocked Rules ---
  const rulesBar = document.getElementById("blocked-rules-bar");
  rulesBar.innerHTML = "";
  if (data.blocked_rules && data.blocked_rules.length > 0) {
    data.blocked_rules.forEach((rule) => {
      const tag = document.createElement("div");
      tag.className = "blocked-rule-tag";
      tag.innerHTML = `
        <span class="blocked-rule-tag__type">${escapeHtml(rule.type)}</span>
        🚫 ${escapeHtml(rule.value)}
      `;
      rulesBar.appendChild(tag);
    });
  }

  // --- Summary Stats ---
  animateValue("stat-total-packets", data.summary.total_packets);
  animateValue("stat-total-bytes", data.summary.total_bytes);
  document.getElementById("stat-total-bytes-human").textContent = formatBytes(data.summary.total_bytes);
  animateValue("stat-tcp", data.summary.tcp_packets);
  animateValue("stat-udp", data.summary.udp_packets);
  animateValue("stat-forwarded", data.summary.forwarded);
  animateValue("stat-dropped", data.summary.dropped);

  // --- Protocol Doughnut Chart ---
  renderProtocolChart(data.summary);

  // --- App Breakdown Bar Chart ---
  renderAppChart(data.app_breakdown);

  // --- Thread Stats Charts ---
  renderLBChart(data.thread_stats.load_balancers);
  renderFPChart(data.thread_stats.fast_paths);

  // --- Detected Domains Table ---
  renderDomainsTable(data.detected_domains);
}

// ============================================================
// Charts
// ============================================================

function renderProtocolChart(summary) {
  const ctx = document.getElementById("chart-protocol").getContext("2d");

  if (chartProtocol) chartProtocol.destroy();

  chartProtocol = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["TCP", "UDP"],
      datasets: [
        {
          data: [summary.tcp_packets, summary.udp_packets],
          backgroundColor: [getColorAlpha(0, 0.8), getColorAlpha(1, 0.8)],
          borderColor: [getColor(0), getColor(1)],
          borderWidth: 2,
          hoverBorderWidth: 3,
          hoverOffset: 8,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: "68%",
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            padding: 20,
            font: { size: 13, weight: "600" },
          },
        },
        tooltip: {
          backgroundColor: "rgba(13, 17, 23, 0.95)",
          titleFont: { size: 13, weight: "700" },
          bodyFont: { size: 12 },
          padding: 12,
          cornerRadius: 8,
          borderColor: "rgba(255,255,255,0.08)",
          borderWidth: 1,
          callbacks: {
            label: function (ctx) {
              const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
              const pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
              return ` ${ctx.label}: ${ctx.parsed.toLocaleString()} packets (${pct}%)`;
            },
          },
        },
      },
      animation: {
        animateRotate: true,
        duration: 1000,
        easing: "easeOutQuart",
      },
    },
  });
}

function renderAppChart(appBreakdown) {
  const ctx = document.getElementById("chart-apps").getContext("2d");

  if (chartApps) chartApps.destroy();

  // Sort by count descending
  const sorted = [...appBreakdown].sort((a, b) => b.count - a.count);
  const labels = sorted.map((a) => a.app);
  const counts = sorted.map((a) => a.count);
  const colors = sorted.map((_, i) => getColor(i));
  const bgColors = sorted.map((_, i) => getColorAlpha(i, 0.7));

  chartApps = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "Packets",
          data: counts,
          backgroundColor: bgColors,
          borderColor: colors,
          borderWidth: 1,
          borderRadius: 6,
          borderSkipped: false,
          barThickness: labels.length > 12 ? 14 : 22,
        },
      ],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(13, 17, 23, 0.95)",
          titleFont: { size: 13, weight: "700" },
          bodyFont: { size: 12 },
          padding: 12,
          cornerRadius: 8,
          borderColor: "rgba(255,255,255,0.08)",
          borderWidth: 1,
          callbacks: {
            label: function (ctx) {
              const item = sorted[ctx.dataIndex];
              return ` ${item.count} packets (${item.percentage}%)`;
            },
          },
        },
      },
      scales: {
        x: {
          grid: { color: "rgba(255,255,255,0.04)", drawBorder: false },
          ticks: { font: { size: 11 } },
        },
        y: {
          grid: { display: false },
          ticks: { font: { size: 11, weight: "600" } },
        },
      },
      animation: {
        duration: 800,
        easing: "easeOutQuart",
      },
    },
  });

  // Set dynamic height based on number of items
  const canvas = document.getElementById("chart-apps");
  canvas.parentElement.style.height = Math.max(200, sorted.length * 34) + "px";
}

function renderLBChart(loadBalancers) {
  const ctx = document.getElementById("chart-lb").getContext("2d");

  if (chartLB) chartLB.destroy();

  const labels = loadBalancers.map((lb) => `LB ${lb.id}`);
  const values = loadBalancers.map((lb) => lb.dispatched);

  chartLB = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "Dispatched",
          data: values,
          backgroundColor: loadBalancers.map((_, i) => getColorAlpha(i + 3, 0.7)),
          borderColor: loadBalancers.map((_, i) => getColor(i + 3)),
          borderWidth: 1,
          borderRadius: 8,
          borderSkipped: false,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(13, 17, 23, 0.95)",
          padding: 12,
          cornerRadius: 8,
          borderColor: "rgba(255,255,255,0.08)",
          borderWidth: 1,
        },
      },
      scales: {
        x: { grid: { display: false } },
        y: {
          grid: { color: "rgba(255,255,255,0.04)", drawBorder: false },
          beginAtZero: true,
          ticks: { font: { size: 11 } },
        },
      },
      animation: { duration: 800, easing: "easeOutQuart" },
    },
  });
}

function renderFPChart(fastPaths) {
  const ctx = document.getElementById("chart-fp").getContext("2d");

  if (chartFP) chartFP.destroy();

  const labels = fastPaths.map((fp) => `FP ${fp.id}`);
  const values = fastPaths.map((fp) => fp.processed);

  chartFP = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "Processed",
          data: values,
          backgroundColor: fastPaths.map((_, i) => getColorAlpha(i + 5, 0.7)),
          borderColor: fastPaths.map((_, i) => getColor(i + 5)),
          borderWidth: 1,
          borderRadius: 8,
          borderSkipped: false,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(13, 17, 23, 0.95)",
          padding: 12,
          cornerRadius: 8,
          borderColor: "rgba(255,255,255,0.08)",
          borderWidth: 1,
        },
      },
      scales: {
        x: { grid: { display: false } },
        y: {
          grid: { color: "rgba(255,255,255,0.04)", drawBorder: false },
          beginAtZero: true,
          ticks: { font: { size: 11 } },
        },
      },
      animation: { duration: 800, easing: "easeOutQuart" },
    },
  });
}

// ============================================================
// Domains Table
// ============================================================

let allDomains = [];

function renderDomainsTable(domains) {
  allDomains = domains || [];
  filterDomains("");
}

function filterDomains(query) {
  const tbody = document.getElementById("domains-tbody");
  tbody.innerHTML = "";

  const q = query.toLowerCase();
  const filtered = allDomains.filter(
    (d) =>
      d.domain.toLowerCase().includes(q) || d.app.toLowerCase().includes(q)
  );

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="3" style="text-align: center; padding: 32px; color: var(--text-muted);">
          ${allDomains.length === 0 ? "No domains detected" : "No matching domains"}
        </td>
      </tr>
    `;
    return;
  }

  filtered.forEach((d, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="color: var(--text-muted); font-size: 0.75rem; width: 40px;">${i + 1}</td>
      <td>${escapeHtml(d.domain)}</td>
      <td><span class="app-badge">${escapeHtml(d.app)}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// Search handler
domainSearch.addEventListener("input", (e) => {
  filterDomains(e.target.value);
});

// ============================================================
// Utilities
// ============================================================

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function animateValue(elementId, targetValue) {
  const el = document.getElementById(elementId);
  const duration = 800;
  const start = performance.now();
  const startValue = 0;

  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // easeOutQuart
    const eased = 1 - Math.pow(1 - progress, 4);
    const current = Math.round(startValue + (targetValue - startValue) * eased);
    el.textContent = current.toLocaleString();

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function showError(message) {
  errorText.textContent = message;
  errorBanner.classList.add("visible");
}

function hideError() {
  errorBanner.classList.remove("visible");
}
