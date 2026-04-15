let riskChart;
let labelChart;
let timelineChart;
let protocolChart;
let pollHandle;
let statusFlashTimer;
const interfaceDetails = new Map();

const el = (id) => document.getElementById(id);

async function api(path, options = {}) {
    const response = await fetch(path, options);
    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || data.message || "Request failed");
    }
    return data;
}

function setStatus(message) {
    el("statusMessage").textContent = message;
    const flash = el("statusFlash");
    if (!flash) return;
    flash.hidden = false;
    flash.textContent = message;
    flash.classList.add("visible");
    if (statusFlashTimer) window.clearTimeout(statusFlashTimer);
    statusFlashTimer = window.setTimeout(() => {
        flash.classList.remove("visible");
        flash.hidden = true;
    }, 4200);
}

function riskClass(risk) {
    return `risk-${String(risk || "normal").toLowerCase()}`;
}

function renderDoughnut(chartRef, canvasId, labels, values, title, colors) {
    const canvas = el(canvasId);
    if (!canvas) return chartRef;
    if (chartRef) chartRef.destroy();

    const hasData = labels?.length && values?.length;
    return new Chart(canvas.getContext("2d"), {
        type: "doughnut",
        data: {
            labels: hasData ? labels : ["No data"],
            datasets: [{
                data: hasData ? values : [1],
                backgroundColor: hasData ? colors : ["#303030"],
                borderColor: "#040404",
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: "#f7f7f7" } },
                title: { display: true, text: title, color: "#f7f7f7" },
            },
        },
    });
}

function renderBar(chartRef, canvasId, labels, datasets, stacked = false) {
    const canvas = el(canvasId);
    if (!canvas) return chartRef;
    if (chartRef) chartRef.destroy();

    return new Chart(canvas.getContext("2d"), {
        type: "bar",
        data: { labels, datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { stacked, ticks: { color: "#f7f7f7" }, grid: { color: "rgba(255,255,255,0.08)" } },
                y: { stacked, ticks: { color: "#f7f7f7" }, grid: { color: "rgba(255,255,255,0.08)" } },
            },
            plugins: {
                legend: { labels: { color: "#f7f7f7" } },
            },
        },
    });
}

function activateTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.tab === tabName);
    });
    document.querySelectorAll(".tab-panel").forEach((panel) => {
        panel.classList.toggle("active", panel.dataset.panel === tabName);
    });
}

async function loadInterfaces() {
    const data = await api("/interfaces");
    const select = el("iface");
    const previousValue = select.value;
    interfaceDetails.clear();
    select.innerHTML = "";
    data.interfaces.forEach((iface) => {
        const option = document.createElement("option");
        option.value = iface;
        option.textContent = iface;
        select.appendChild(option);
    });
    (data.details || []).forEach((detail) => {
        interfaceDetails.set(detail.name, detail);
    });
    if (previousValue && data.interfaces.includes(previousValue)) {
        select.value = previousValue;
    } else if (!select.value && data.recommended_target_iface && data.interfaces.includes(data.recommended_target_iface)) {
        select.value = data.recommended_target_iface;
    }
    syncAttackTargetFromInterface(true);
}

async function loadAttackCatalog() {
    const data = await api("/attack_catalog");
    const select = el("attackType");
    select.innerHTML = "";
    Object.entries(data.attacks).forEach(([value, spec]) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = spec.label;
        option.dataset.hint = spec.hint;
        option.dataset.defaultPort = spec.default_port || "";
        option.dataset.defaultCount = spec.default_count;
        select.appendChild(option);
    });
    updateAttackHint();
}

async function loadPcapCatalog() {
    const data = await api("/pcap_catalog");
    const select = el("pcapFile");
    select.innerHTML = "";

    (data.pcaps || []).forEach((pcap) => {
        const option = document.createElement("option");
        option.value = pcap.name;
        const sizeMb = pcap.size_bytes ? ` (${(pcap.size_bytes / (1024 * 1024)).toFixed(2)} MB)` : "";
        option.textContent = `${pcap.name}${sizeMb}`;
        option.dataset.sizeBytes = pcap.size_bytes || 0;
        select.appendChild(option);
    });

    updatePcapHint();
}

async function uploadPcap() {
    const input = el("pcapUpload");
    const file = input.files?.[0];
    if (!file) {
        setStatus("Choose a .pcap file first.");
        return;
    }

    const button = el("uploadPcapBtn");
    button.disabled = true;
    const previousLabel = button.textContent;
    button.textContent = "Uploading...";
    try {
        const form = new FormData();
        form.append("file", file);
        const response = await fetch("/upload_pcap", {
            method: "POST",
            body: form,
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Upload failed");
        }
        await loadPcapCatalog();
        el("pcapFile").value = data.pcap?.name || el("pcapFile").value;
        updatePcapHint();
        input.value = "";
        setStatus(`Uploaded ${data.pcap?.name || file.name} and added it to the replay catalog.`);
    } finally {
        button.disabled = false;
        button.textContent = previousLabel;
    }
}

function updateAttackHint() {
    const selected = el("attackType").selectedOptions[0];
    if (!selected) return;
    if (selected.dataset.defaultPort) el("targetPort").value = selected.dataset.defaultPort;
    if (selected.dataset.defaultCount) el("packetCount").value = selected.dataset.defaultCount;
    syncAttackTargetFromInterface();
}

function getSelectedInterfaceDetails() {
    return interfaceDetails.get(el("iface").value) || null;
}

function selectedInterfaceIp() {
    return getSelectedInterfaceDetails()?.primary_ipv4 || "";
}

function syncAttackTargetFromInterface(force = false) {
    const targetInput = el("targetIp");
    const iface = el("iface").value;
    const selected = el("attackType").selectedOptions[0];
    const resolvedIp = selectedInterfaceIp() || "127.0.0.1";
    const wasAutoManaged = targetInput.dataset.autoManaged !== "false";
    const currentValue = targetInput.value.trim();
    const shouldUpdate = force || wasAutoManaged || !currentValue || currentValue === "127.0.0.1";

    if (shouldUpdate) {
        targetInput.value = resolvedIp;
        targetInput.dataset.autoManaged = "true";
    }

    const sourceLabel = iface || "best available interface";
    const modeLabel = targetInput.dataset.autoManaged === "false" ? "manual override active" : `auto target ${resolvedIp} from ${sourceLabel}`;
    el("attackHint").textContent = `${selected?.dataset.hint || "Send a real traffic pattern into the detector."} Real Test will use ${modeLabel}.`;
}

function updatePcapHint() {
    const selected = el("pcapFile").selectedOptions[0];
    const iface = el("iface").value || "selected interface";
    if (!selected) {
        el("pcapHint").textContent = "No PCAP files found in the test-kit folder.";
        return;
    }
    el("pcapHint").textContent = `Replay ${selected.value} on ${iface} and score the replayed packets directly in the IDS.`;
}

async function refreshHealth() {
    const data = await api("/health");
    el("captureState").textContent = data.capturing ? `Capturing on ${data.selected_iface}` : "Idle";
    el("captureDot").classList.toggle("active", data.capturing);
    el("healthText").textContent = data.capture_error || (data.models_loaded ? "All layered detection and prevention services online." : `Models unavailable: ${data.model_error || "unknown error"}`);
    el("captureMode").textContent = data.capturing ? "Live Capture" : "Standby";
    if (data.selected_iface && el("iface").value !== data.selected_iface && data.capturing) {
        el("iface").value = data.selected_iface;
        syncAttackTargetFromInterface();
    }
}

async function refreshPrevention() {
    const data = await api("/prevention");
    el("preventionToggle").checked = data.enabled;
    el("threshold").value = data.auto_block_threshold;
}

async function refreshHealing() {
    const data = await api("/healing");
    el("healingToggle").checked = data.enabled;
    el("healingWindow").value = data.healing_window_seconds;
}

function renderResults(results, blockedItems = []) {
    const tbody = el("resultsTable");
    tbody.innerHTML = "";
    const blockedSet = new Set((blockedItems || []).map((item) => item.ip));

    results.slice(0, 50).forEach((row) => {
        const tr = document.createElement("tr");
        const ip = resolveRowActionIp(row);
        const preventionSuccess = Boolean(row.prevention_result?.success);
        const isBlocked = ip && (blockedSet.has(ip) || preventionSuccess);
        const actionMarkup = !ip
            ? ""
            : isBlocked
                ? `<button class="action-btn unblock" data-ip="${ip}" data-action="heal">Heal</button>`
                : `<button class="action-btn block" data-ip="${ip}" data-action="block">Block</button>`;
        tr.innerHTML = `
            <td class="mono">${(row.timestamp || "").slice(11, 19)}</td>
            <td class="mono">${row.flow_key?.src_ip || ""} -> ${row.flow_key?.dst_ip || ""}:${row.flow_key?.dport || ""}</td>
            <td>${row.proto_name || row.flow_key?.proto || ""}</td>
            <td>${row.rf_labels || "BENIGN"}</td>
            <td>${row.gbdt_labels || "n/a"}</td>
            <td>${row.ppo_risk || "n/a"}</td>
            <td>${row.gnn_label || "n/a"}</td>
            <td><span class="risk-pill ${riskClass(row.severity || row.ensemble_risk)}">${row.severity || row.ensemble_risk || "normal"}</span></td>
            <td class="mono">${ip || "n/a"}</td>
            <td>${actionMarkup}</td>
        `;
        tbody.appendChild(tr);
    });

    el("tableSummary").textContent = `${results.length} recent flows loaded`;
}

function isTargetableIp(ip) {
    if (!ip) return false;
    const value = String(ip).trim();
    if (!value) return false;
    if (["127.0.0.1", "::1", "0.0.0.0", "::"].includes(value)) return false;
    if (value.endsWith(".255")) return false;
    if (value.startsWith("224.") || value.startsWith("239.") || value.startsWith("ff")) return false;
    return true;
}

function resolveRowActionIp(row) {
    const candidate = String(row?.candidate_block_ip || "").trim();
    if (isTargetableIp(candidate)) return candidate;

    const srcIp = String(row?.flow_key?.src_ip || "").trim();
    const dstIp = String(row?.flow_key?.dst_ip || "").trim();
    const localIp = selectedInterfaceIp();

    const ranked = [srcIp, dstIp].filter((ip) => isTargetableIp(ip));
    const nonLocal = ranked.find((ip) => ip !== localIp);
    return nonLocal || ranked[0] || "";
}

function renderHighRisk(results) {
    const tbody = el("highRiskTable");
    const summary = el("highRiskSummary");
    if (!tbody || !summary) return;
    tbody.innerHTML = "";

    const highRisk = (results || [])
        .filter((row) => ["high", "medium"].includes(String(row.severity || row.ensemble_risk || "").toLowerCase()))
        .sort((a, b) => {
            const rank = { high: 2, medium: 1, low: 0, normal: -1 };
            return (rank[String(b.severity || b.ensemble_risk || "").toLowerCase()] || -1)
                - (rank[String(a.severity || a.ensemble_risk || "").toLowerCase()] || -1);
        });

    if (!highRisk.length) {
        tbody.innerHTML = `<tr><td colspan="8">No medium or high risk flows in the current window.</td></tr>`;
        summary.textContent = "No medium/high risk flows yet";
        return;
    }

    highRisk.slice(0, 25).forEach((row) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="mono">${(row.timestamp || "").slice(11, 19)}</td>
            <td class="mono">${row.flow_key?.src_ip || ""} -> ${row.flow_key?.dst_ip || ""}:${row.flow_key?.dport || ""}</td>
            <td>${row.proto_name || row.flow_key?.proto || ""}</td>
            <td><span class="risk-pill ${riskClass(row.severity || row.ensemble_risk)}">${row.severity || row.ensemble_risk || "normal"}</span></td>
            <td>${row.rf_labels || "BENIGN"}</td>
            <td>${row.gbdt_labels || "n/a"}</td>
            <td>${(row.heuristics || []).join(", ") || "none"}</td>
            <td class="mono">${row.candidate_block_ip || "n/a"}</td>
        `;
        tbody.appendChild(tr);
    });

    summary.textContent = `${highRisk.length} medium/high risk flows in view`;
}

function renderCaptureDebug(items, captureStats) {
    const tbody = el("captureDebugTable");
    const summary = el("captureDebugSummary");
    if (!tbody || !summary) return;
    tbody.innerHTML = "";

    const totalPackets = captureStats?.packets_total || 0;
    const icmpPackets = captureStats?.proto_ICMP || 0;
    const tcpPackets = captureStats?.proto_TCP || 0;
    const filteredItems = (items || []).filter((row) => !(row.src_ip === "127.0.0.1" && row.dst_ip === "127.0.0.1"));
    const hiddenLoopback = Math.max(0, (items || []).length - filteredItems.length);
    summary.textContent = `Captured ${totalPackets} packets | ICMP ${icmpPackets} | TCP ${tcpPackets} | hidden local loopback rows ${hiddenLoopback}`;

    if (!filteredItems.length) {
        if (items?.length) {
            tbody.innerHTML = `<tr><td colspan="7">Only local loopback app traffic is being hidden here. This panel is for advanced capture troubleshooting, not normal monitoring.</td></tr>`;
            return;
        }
        tbody.innerHTML = `<tr><td colspan="7">No captured packet summaries yet.</td></tr>`;
        return;
    }

    filteredItems.slice(0, 25).forEach((row) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="mono">${(row.timestamp || "").slice(11, 19)}</td>
            <td class="mono">${row.iface || "n/a"}</td>
            <td>${row.proto_name || row.proto || "n/a"}</td>
            <td class="mono">${row.src_ip || "n/a"}</td>
            <td class="mono">${row.dst_ip || "n/a"}</td>
            <td>${row.dport || row.sport || "n/a"}</td>
            <td>${row.length || 0}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderAlerts(alerts, blockedItems = []) {
    const host = el("alertsList");
    host.innerHTML = "";
    const blockedSet = new Set((blockedItems || []).map((item) => item.ip));
    if (!alerts.length) {
        host.innerHTML = `<div class="event-card">No alerts yet.</div>`;
        return;
    }

    alerts.slice(0, 20).forEach((alert) => {
        const item = document.createElement("div");
        item.className = "event-card";
        const ip = alert.candidate_block_ip || "";
        const actionMarkup = !ip
            ? ""
            : blockedSet.has(ip)
                ? `<button class="action-btn unblock" data-ip="${ip}" data-action="heal">Heal</button>`
                : `<button class="action-btn block" data-ip="${ip}" data-action="block">Block</button>`;
        item.innerHTML = `
            <div class="card-head">
                <strong>${alert.title}</strong>
                <span class="risk-pill ${riskClass(alert.severity)}">${alert.severity}</span>
            </div>
            <div>${alert.message}</div>
            <div class="helper mono">${(alert.timestamp || "").replace("T", " ").slice(0, 19)} | ${alert.src_ip} -> ${alert.dst_ip}</div>
            ${ip ? `<div class="helper mono">Candidate IP: ${ip}</div>` : ""}
            ${actionMarkup ? `<div class="alert-actions">${actionMarkup}</div>` : ""}
        `;
        host.appendChild(item);
    });
}

function renderBlocked(items) {
    const host = el("blockedList");
    const overviewHost = el("overviewBlockedList");
    const renderInto = (target) => {
        if (!target) return;
        target.innerHTML = "";
        if (!items.length) {
            target.innerHTML = `<div class="event-card">No firewall blocks active.</div>`;
            return;
        }

        items.forEach((item) => {
            const card = document.createElement("div");
            card.className = "event-card";
            const status = item.status || (item.applied ? "active" : "pending");
            const source = String(item.block_source || "manual").toUpperCase();
            const recovery = item.heal_at ? `Recovery scheduled: ${String(item.heal_at).replace("T", " ").slice(0, 19)} UTC` : "Recovery: manual only";
            card.innerHTML = `
                <div class="card-head">
                    <strong class="mono">${item.ip}</strong>
                    <button class="action-btn unblock" data-ip="${item.ip}" data-action="heal">Heal</button>
                </div>
                <div>${item.message || item.reason || "Firewall rule present."}</div>
                <div class="helper">${item.reason || "No reason provided"}</div>
                <div class="helper">Status: ${status} | Source: ${source}</div>
                <div class="helper">${recovery}</div>
            `;
            target.appendChild(card);
        });
    };

    renderInto(host);
    renderInto(overviewHost);
}

function renderHealingQueue(items) {
    const host = el("healingQueueList");
    if (!host) return;
    host.innerHTML = "";
    if (!items.length) {
        host.innerHTML = `<div class="event-card">No auto-healing actions are currently scheduled.</div>`;
        return;
    }

    items
        .slice()
        .sort((a, b) => String(a.heal_at || "").localeCompare(String(b.heal_at || "")))
        .slice(0, 12)
        .forEach((item) => {
            const card = document.createElement("div");
            card.className = "event-card";
            card.innerHTML = `
                <div class="card-head">
                    <strong class="mono">${item.ip}</strong>
                    <button class="action-btn unblock" data-ip="${item.ip}" data-action="heal">Heal Now</button>
                </div>
                <div>${item.reason || "Auto-blocked host pending recovery."}</div>
                <div class="helper">Scheduled recovery: ${item.heal_at ? String(item.heal_at).replace("T", " ").slice(0, 19) : "n/a"} UTC</div>
                <div class="helper">Healing state: ${item.heal_status || "scheduled"}</div>
            `;
            host.appendChild(card);
        });
}

function renderHealingHistory(items) {
    const host = el("healingHistoryList");
    if (!host) return;
    host.innerHTML = "";
    if (!items.length) {
        host.innerHTML = `<div class="event-card">No healing actions have been recorded yet.</div>`;
        return;
    }

    items.slice(0, 12).forEach((item) => {
        const card = document.createElement("div");
        card.className = "event-card";
        card.innerHTML = `
            <div class="card-head">
                <strong class="mono">${item.ip}</strong>
                <span class="risk-pill ${item.healed ? "risk-low" : "risk-medium"}">${item.healed ? "recovered" : "retry"}</span>
            </div>
            <div>${item.message || "Recovery action executed."}</div>
            <div class="helper">Trigger: ${item.trigger || "manual"} | Source: ${item.block_source || "unknown"}</div>
            <div class="helper mono">${String(item.healed_at || item.requested_at || "").replace("T", " ").slice(0, 19)}</div>
        `;
        host.appendChild(card);
    });
}

function renderComparison(modelComparison) {
    const host = el("comparisonGrid");
    host.innerHTML = "";
    const entries = [
        ["Autoencoder", modelComparison.autoencoder],
        ["Isolation Forest", modelComparison.isolation_forest],
        ["K-Means", modelComparison.kmeans],
        ["Random Forest", modelComparison.random_forest],
        ["Gradient Boosted Tree", modelComparison.gradient_boosted_tree],
        ["PPO Policy", modelComparison.ppo_policy],
        ["GNN Detector", modelComparison.gnn_detector],
    ];

    entries.forEach(([label, stats]) => {
        if (!stats) return;
        const card = document.createElement("div");
        card.className = "comparison-card";
        const primaryValue = stats.primary_value ?? 0;
        const pct = (stats.pct ?? 0).toFixed(1);
        card.innerHTML = `
            <div>${label}</div>
            <strong>${primaryValue}</strong>
            <span>${stats.metric_label || "Flagged"} | ${pct}% of flows</span>
            <span>${stats.secondary_label || "detail"}: ${stats.secondary_value ?? "n/a"}</span>
            ${typeof stats.high_count === "number" ? `<span>high only: ${stats.high_count}</span>` : ""}
        `;
        host.appendChild(card);
    });
}

function renderModelMatrix(matrix) {
    const host = el("modelMatrix");
    host.innerHTML = "";
    Object.entries(matrix || {}).forEach(([key, value]) => {
        const card = document.createElement("div");
        card.className = "mini-metric";
        card.innerHTML = `
            <span>${key.toUpperCase()}</span>
            <strong>${value.flagged ?? 0}</strong>
            <small>${value.pct ?? 0}% flagged</small>
            <small>${value.avg_score != null ? `avg score ${value.avg_score}` : `top ${value.top_label || "n/a"}`}</small>
        `;
        host.appendChild(card);
    });
}

function renderModelNarrative(analysis) {
    const host = el("modelNarrative");
    host.innerHTML = "";
    const lines = [
        `Core anomaly engine: Autoencoder, Isolation Forest, and K-Means provide the layered anomaly stack from the prototype review.`,
        `Live decision authority: Random Forest and Gradient Boosted Tree verify traffic before severity is raised in production.`,
        `Research assist layers: PPO and GNN remain visible for experimentation, benchmarking, and operator context only.`,
        `Active defense goal: suspicious traffic is surfaced with candidate block targets so prevention and healing workflows stay operator-ready.`,
    ];
    lines.forEach((line) => {
        const item = document.createElement("div");
        item.className = "event-card compact-card";
        item.textContent = line;
        host.appendChild(item);
    });
}

function renderWorkflowPanel(status, analysis) {
    const host = el("workflowPanel");
    if (!host) return;
    host.innerHTML = "";
    const items = [
        "Input: live packet capture and normalized flow aggregation feed the layered engine.",
        "Clean: traffic is standardized, feature-aligned, and de-noised before scoring.",
        `Layer 1: Autoencoder anomaly coverage is ${(analysis.ae_anomalies?.pct || 0).toFixed(1)}% of current flows.`,
        `Layer 2: Isolation Forest and K-Means monitor outlier drift across the current session.`,
        "Verification: Random Forest plus Gradient Boosted Tree are the authority for live severity.",
        `Active Defense: auto-blocking is ${status.prevention_enabled ? "enabled" : "disabled"} at the ${status.auto_block_threshold || "high"} threshold.`,
        `Healing: ${status.healing_enabled ? `enabled with a ${status.healing_window_seconds || 180}s recovery window` : "disabled, operator recovery only"}.`,
    ];
    items.forEach((text) => {
        const card = document.createElement("div");
        card.className = "event-card compact-card";
        card.textContent = text;
        host.appendChild(card);
    });
}

function renderDefenseSnapshot(status, analysis) {
    const host = el("defenseSnapshot");
    if (!host) return;
    host.innerHTML = "";
    const high = analysis.risk_distribution?.high || 0;
    const medium = analysis.risk_distribution?.medium || 0;
    const stats = analysis.capture_stats || {};
    const items = [
        `Posture: ${high > 0 ? "high-risk activity observed" : medium > 0 ? "elevated review posture" : "baseline traffic posture"}.`,
        `Capture volume: ${stats.packets_total || 0} packets observed, including ${stats.proto_TCP || 0} TCP and ${stats.proto_ICMP || 0} ICMP packets.`,
        `Live authority order: heuristics, Random Forest, and Gradient Boosted Tree; assist layers remain advisory only.`,
        `Operational state: ${analysis.alerts_count || 0} alerts, ${analysis.blocked_count || 0} blocked IPs, ${(analysis.healing_history || []).length} healing actions, ${(analysis.attack_runs || []).length} recorded test runs.`,
    ];
    items.forEach((text) => {
        const card = document.createElement("div");
        card.className = "event-card compact-card";
        card.textContent = text;
        host.appendChild(card);
    });
}

function renderDefenseDoctrine(status, analysis) {
    const host = el("defenseDoctrine");
    if (!host) return;
    host.innerHTML = "";
    const items = [
        "Mission: reduce operator noise by combining layered anomaly detectors with verification models and explicit prevention policy.",
        "Core product alignment: the anomaly stack is Autoencoder, Isolation Forest, and K-Means, matching the prototype review.",
        "Production live alerts: RF and GBDT decide severity; heuristics raise explicit ICMP, TCP probe, SYN burst, and UDP flood events.",
        `Prevention posture: ${status.prevention_enabled ? "automatic blocking is armed" : "blocking remains manual"} with threshold set to ${status.auto_block_threshold || "high"}.`,
        `Healing posture: ${status.healing_enabled ? `automatic recovery is active after ${status.healing_window_seconds || 180} seconds` : "recovery remains manual until healing is re-enabled"}.`,
        `Research visibility: PPO and GNN remain in the console for deeper context, but they do not overrule live authority.`,
    ];
    items.forEach((text) => {
        const card = document.createElement("div");
        card.className = "event-card compact-card";
        card.textContent = text;
        host.appendChild(card);
    });
}

function renderPreventionQueue(results, blockedItems = []) {
    const tbody = el("preventionQueueTable");
    if (!tbody) return;
    tbody.innerHTML = "";
    const blockedSet = new Set((blockedItems || []).map((item) => item.ip));
    const seen = new Set();
    const queue = (results || []).filter((row) => {
        const severity = String(row.severity || row.ensemble_risk || "").toLowerCase();
        const heuristics = row.heuristics || [];
        const rfLabel = String(row.rf_labels || "BENIGN").toUpperCase();
        const gbdtLabel = String(row.gbdt_labels || "BENIGN").toUpperCase();
        return row.candidate_block_ip && (
            severity === "high"
            || severity === "medium"
            || heuristics.length > 0
            || rfLabel !== "BENIGN"
            || gbdtLabel !== "BENIGN"
        );
    }).filter((row) => {
        const key = `${row.candidate_block_ip}|${row.flow_key?.src_ip}|${row.flow_key?.dst_ip}|${row.flow_key?.dport}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    if (!queue.length) {
        tbody.innerHTML = `<tr><td colspan="4">No actionable prevention candidates in the current window.</td></tr>`;
        return;
    }

    queue.slice(0, 12).forEach((row) => {
        const candidate = row.candidate_block_ip || "n/a";
        const reason = (row.heuristics || []).join(", ") || row.rf_labels || row.gbdt_labels || "operator review";
        const blockedLabel = blockedSet.has(candidate) ? "blocked" : candidate;
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="mono">${row.flow_key?.src_ip || ""} -> ${row.flow_key?.dst_ip || ""}:${row.flow_key?.dport || ""}</td>
            <td><span class="risk-pill ${riskClass(row.severity || row.ensemble_risk)}">${row.severity || row.ensemble_risk || "normal"}</span></td>
            <td>${reason}</td>
            <td class="mono">${blockedLabel}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderAttackRuns(runs) {
    const tbody = el("attackRunsTable");
    tbody.innerHTML = "";
    const attackRuns = (runs || []).filter((run) => (run.run_kind || "attack_exercise") !== "pcap_replay");
    if (!attackRuns.length) {
        tbody.innerHTML = `<tr><td colspan="6">No attack experiments yet.</td></tr>`;
        return;
    }

    attackRuns.slice(0, 12).forEach((run) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${run.attack_label || run.attack_type}</td>
            <td class="mono">${run.target_ip}${run.target_port ? `:${run.target_port}` : ""}</td>
            <td>${run.packet_count || 0}</td>
            <td>${run.detection_latency_ms != null ? `${run.detection_latency_ms.toFixed(0)} ms` : "pending"}</td>
            <td>${run.prevention_latency_ms != null ? `${run.prevention_latency_ms.toFixed(0)} ms` : "none"}</td>
            <td>${run.matched_flows || 0}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderPcapRuns(runs) {
    const tbody = el("pcapRunsTable");
    const summaryHost = el("pcapReplaySummary");
    if (!tbody || !summaryHost) return;

    tbody.innerHTML = "";
    summaryHost.innerHTML = "";
    const pcapRuns = (runs || []).filter((run) => run.run_kind === "pcap_replay");
    if (!pcapRuns.length) {
        tbody.innerHTML = `<tr><td colspan="6">No PCAP replay runs yet.</td></tr>`;
        summaryHost.innerHTML = `<div class="mini-metric"><span>Replay Status</span><strong>Idle</strong></div>`;
        return;
    }

    const latest = pcapRuns[0];
    const latestStatus = String(latest.replay_status || "completed").toLowerCase();
    const latestStatusLabel = latestStatus === "running"
        ? "Running"
        : latestStatus === "failed"
            ? "Failed"
            : "Completed";
    const summaryItems = [
        ["Latest PCAP", latest.pcap_name || "n/a"],
        ["Replay Status", latestStatusLabel],
        ["Replay Progress", latestStatus === "running" ? `${Number(latest.replay_progress_pct || 0).toFixed(1)}%` : "100.0%"],
        ["Attack-like Flows", latest.attack_candidate_flows || 0],
        ["IDS Detections", latest.detection_count || 0],
        ["Detection Rate", `${Number(latest.detection_rate_pct || 0).toFixed(1)}%`],
    ];
    summaryItems.forEach(([label, value]) => {
        const card = document.createElement("div");
        card.className = "mini-metric";
        card.innerHTML = `<span>${label}</span><strong>${value}</strong>`;
        summaryHost.appendChild(card);
    });

    pcapRuns.slice(0, 12).forEach((run) => {
        const tr = document.createElement("tr");
        const runStatus = String(run.replay_status || "completed").toLowerCase();
        const detectionCell = runStatus === "running"
            ? "Processing..."
            : runStatus === "failed"
                ? "Failed"
                : (run.detection_count || 0);
        tr.innerHTML = `
            <td>${run.pcap_name || "unknown"}</td>
            <td>${runStatus === "running" ? `${run.sent_packet_count || 0}/${run.packet_count || 0}` : (run.packet_count || 0)}</td>
            <td>${run.total_flow_count || run.matched_flows || 0}</td>
            <td>${run.attack_candidate_flows || 0}</td>
            <td>${detectionCell}</td>
            <td>${runStatus === "running" ? `${Number(run.replay_progress_pct || 0).toFixed(1)}%` : `${Number(run.detection_rate_pct || 0).toFixed(1)}%`}</td>
        `;
        tbody.appendChild(tr);
    });
}

function renderTopTalkers(items) {
    const tbody = el("topTalkersTable");
    tbody.innerHTML = "";
    if (!items?.length) {
        tbody.innerHTML = `<tr><td colspan="2">No flow concentration yet.</td></tr>`;
        return;
    }
    items.forEach((item) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td class="mono">${item.flow}</td><td>${item.count}</td>`;
        tbody.appendChild(tr);
    });
}

function renderFeatureHighlights(features) {
    const host = el("featureHighlights");
    host.innerHTML = "";
    Object.entries(features || {}).forEach(([key, value]) => {
        const card = document.createElement("div");
        card.className = "mini-metric";
        card.innerHTML = `<span>${key.replaceAll("_", " ")}</span><strong>${value}</strong>`;
        host.appendChild(card);
    });
}

function renderOpsChecklist(analysis) {
    const host = el("opsChecklist");
    host.innerHTML = "";
    const items = [
        `Review ${analysis.alerts_count || 0} alerts for escalation candidates.`,
        `Validate blocked hosts against ${analysis.blocked_count || 0} current firewall entries.`,
        `Review ${(analysis.healing_queue || []).length} scheduled recoveries and ${(analysis.healing_history || []).length} recent heal actions.`,
        `Compare RF vs GBDT when labels diverge on high-risk flows.`,
        `Use experiments view to verify that injected traffic is detected in acceptable time.`,
    ];
    items.forEach((text) => {
        const card = document.createElement("div");
        card.className = "event-card compact-card";
        card.textContent = text;
        host.appendChild(card);
    });
}

function renderQuickBand(analysis, status) {
    el("primaryModel").textContent = "Layered Core Stack";
    const high = analysis.risk_distribution?.high || 0;
    const medium = analysis.risk_distribution?.medium || 0;
    el("threatPosture").textContent = high > 0 ? "Containment Focus" : medium > 0 ? "Elevated Review" : "Baseline";
    el("captureMode").textContent = status.capturing ? "Live Capture" : "Standby";
}

async function refreshDashboard() {
    const [status, analysis, results, alerts, blocked] = await Promise.all([
        api("/status"),
        api("/analysis"),
        api("/results?limit=100"),
        api("/alerts"),
        api("/blocked_ips"),
    ]);

    el("startBtn").disabled = status.capturing;
    el("stopBtn").disabled = !status.capturing;
    if (status.selected_iface && (!el("iface").value || status.capturing)) {
        el("iface").value = status.selected_iface;
    }
    el("preventionToggle").checked = Boolean(status.prevention_enabled);
    el("threshold").value = status.auto_block_threshold || "high";
    el("healingToggle").checked = Boolean(status.healing_enabled);
    el("healingWindow").value = status.healing_window_seconds || 180;
    syncAttackTargetFromInterface();
    el("totalFlows").textContent = analysis.total_flows || 0;
    el("alertsCount").textContent = analysis.alerts_count || 0;
    el("blockedCount").textContent = analysis.blocked_count || 0;
    el("anomalyCount").textContent = analysis.ae_anomalies?.count || 0;
    el("agreementPct").textContent = `${(analysis.model_agreement?.pct || 0).toFixed(1)}%`;
    el("avgPps").textContent = analysis.feature_highlights?.avg_packets_per_sec || 0;
    el("avgBps").textContent = analysis.feature_highlights?.avg_bytes_per_sec || 0;
    el("synBurstFlows").textContent = analysis.feature_highlights?.syn_burst_flows || 0;

    const riskDist = analysis.risk_distribution || {};
    riskChart = renderDoughnut(
        riskChart,
        "riskChart",
        Object.keys(riskDist),
        Object.values(riskDist),
        "Flow risk spread",
        ["#6fd6c5", "#7cb8ff", "#ffb26b", "#ff7d63", "#d7e4ec"]
    );

    const labelDist = analysis.rf_classification || {};
    labelChart = renderDoughnut(
        labelChart,
        "labelChart",
        Object.keys(labelDist).slice(0, 8),
        Object.values(labelDist).slice(0, 8),
        "Top detected labels",
        ["#ff7d63", "#ffb26b", "#6fd6c5", "#7cb8ff", "#9fe8df", "#d7e4ec", "#a6c9ff", "#ffc999"]
    );

    const timeline = analysis.severity_timeline || [];
    timelineChart = renderBar(
        timelineChart,
        "timelineChart",
        timeline.map((row) => row.time),
        [
            { label: "Normal", data: timeline.map((row) => row.normal || 0), backgroundColor: "#d7e4ec" },
            { label: "Low", data: timeline.map((row) => row.low || 0), backgroundColor: "#7cb8ff" },
            { label: "Medium", data: timeline.map((row) => row.medium || 0), backgroundColor: "#ffb26b" },
            { label: "High", data: timeline.map((row) => row.high || 0), backgroundColor: "#ff7d63" },
        ],
        true
    );

    const protoRisk = analysis.proto_risk_matrix || {};
    protocolChart = renderBar(
        protocolChart,
        "protocolChart",
        Object.keys(protoRisk),
        [
            { label: "Normal", data: Object.values(protoRisk).map((row) => row.normal || 0), backgroundColor: "#d7e4ec" },
            { label: "Low", data: Object.values(protoRisk).map((row) => row.low || 0), backgroundColor: "#7cb8ff" },
            { label: "Medium", data: Object.values(protoRisk).map((row) => row.medium || 0), backgroundColor: "#ffb26b" },
            { label: "High", data: Object.values(protoRisk).map((row) => row.high || 0), backgroundColor: "#ff7d63" },
        ],
        true
    );

    renderResults(results.results || [], blocked.blocked_ips || []);
    renderHighRisk(results.results || []);
    renderCaptureDebug(analysis.packet_debug || [], analysis.capture_stats || {});
    renderWorkflowPanel(status, analysis);
    renderDefenseSnapshot(status, analysis);
    renderAlerts(alerts.alerts || [], blocked.blocked_ips || []);
    renderBlocked(blocked.blocked_ips || []);
    renderComparison(analysis.model_comparison || {});
    renderModelMatrix(analysis.model_matrix || {});
    renderModelNarrative(analysis);
    renderDefenseDoctrine(status, analysis);
    renderPreventionQueue(results.results || [], blocked.blocked_ips || []);
    renderHealingQueue(analysis.healing_queue || []);
    renderHealingHistory(analysis.healing_history || []);
    renderAttackRuns(analysis.attack_runs || []);
    renderPcapRuns(analysis.attack_runs || []);
    renderTopTalkers(analysis.top_talkers || []);
    renderFeatureHighlights(analysis.feature_highlights || {});
    renderOpsChecklist(analysis);
    renderQuickBand(analysis, status);
    await refreshHealth();
}

async function startCapture() {
    const iface = el("iface").value;
    const data = await api("/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iface }),
    });
    setStatus(`Capture started on ${data.iface}.`);
    await refreshDashboard();
}

async function stopCapture() {
    await api("/stop", { method: "POST" });
    setStatus("Capture stopped.");
    await refreshDashboard();
}

async function clearResults() {
    await api("/clear_results", { method: "POST" });
    setStatus("Results and alerts cleared.");
    await refreshDashboard();
}

async function savePrevention() {
    const enabled = el("preventionToggle").checked;
    const autoBlockThreshold = el("threshold").value;
    const data = await api("/prevention", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled, auto_block_threshold: autoBlockThreshold }),
    });
    const removalNote = data.removed_auto_blocks?.length ? ` Cleared ${data.removed_auto_blocks.length} auto-blocked host(s).` : "";
    setStatus(`Prevention ${enabled ? "enabled" : "disabled"} at ${autoBlockThreshold} threshold.${removalNote}`);
    await refreshDashboard();
}

async function saveHealing() {
    const enabled = el("healingToggle").checked;
    const healingWindowSeconds = Number(el("healingWindow").value || 180);
    await api("/healing", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled, healing_window_seconds: healingWindowSeconds }),
    });
    setStatus(`Healing ${enabled ? "enabled" : "disabled"} with a ${healingWindowSeconds}s recovery window.`);
    await refreshDashboard();
}

async function runAttack() {
    const button = el("simulateBtn");
    const targetInput = el("targetIp");
    const iface = el("iface").value;
    const autoTarget = targetInput.dataset.autoManaged !== "false";
    const resolvedTargetIp = selectedInterfaceIp() || targetInput.value.trim() || "127.0.0.1";
    if (autoTarget) {
        targetInput.value = resolvedTargetIp;
    }
    const payload = {
        attack_type: el("attackType").value,
        iface,
        auto_target: autoTarget,
        target_ip: autoTarget ? resolvedTargetIp : targetInput.value.trim(),
        packet_count: Number(el("packetCount").value || 0),
        target_port: Number(el("targetPort").value || 0),
        start_port: Number(el("targetPort").value || 0),
    };
    button.disabled = true;
    const previousLabel = button.textContent;
    button.textContent = "Sending Real Test...";
    try {
        const data = await api("/simulate_attack", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        const via = data.target_iface ? ` via ${data.target_iface}` : "";
        setStatus(`${data.attack_label} test sent to ${data.target_ip}${via} (${data.packet_count} packets, ${data.duration_seconds}s send time).`);
        setTimeout(refreshDashboard, 1500);
    } finally {
        button.disabled = false;
        button.textContent = previousLabel;
    }
}

async function replayPcap() {
    const button = el("replayPcapBtn");
    const pcapName = el("pcapFile").value;
    if (!pcapName) {
        setStatus("No PCAP file is available to replay.");
        return;
    }

    button.disabled = true;
    const previousLabel = button.textContent;
    button.textContent = "Replaying PCAP...";
    try {
        const data = await api("/replay_pcap", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                pcap_name: pcapName,
                iface: el("iface").value,
                loop_count: Number(el("pcapLoops").value || 1),
                packets_per_second: Number(el("pcapRate").value || 0),
                packet_limit: Number(el("pcapLimit").value || 0),
            }),
        });
        const via = data.iface ? ` via ${data.iface}` : "";
        setStatus(`Started replay for ${data.pcap_name}${via}. Watch the PCAP Replay tab for completion.`);
        setTimeout(refreshDashboard, 1000);
    } finally {
        button.disabled = false;
        button.textContent = previousLabel;
    }
}

async function blockOrUnblock(ip, action) {
    const path = action === "heal" ? "/heal_ip" : action === "unblock" ? "/unblock_ip" : "/block_ip";
    const data = await api(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, reason: "Dashboard operator action" }),
    });
    setStatus(data.message || `${action} completed for ${ip}.`);
    await refreshDashboard();
}

function bindEvents() {
    el("startBtn").addEventListener("click", () => startCapture().catch((err) => setStatus(err.message)));
    el("stopBtn").addEventListener("click", () => stopCapture().catch((err) => setStatus(err.message)));
    el("clearBtn").addEventListener("click", () => clearResults().catch((err) => setStatus(err.message)));
    el("savePreventionBtn").addEventListener("click", () => savePrevention().catch((err) => setStatus(err.message)));
    el("saveHealingBtn").addEventListener("click", () => saveHealing().catch((err) => setStatus(err.message)));
    el("simulateBtn").addEventListener("click", () => runAttack().catch((err) => setStatus(err.message)));
    el("uploadPcapBtn").addEventListener("click", () => uploadPcap().catch((err) => setStatus(err.message)));
    el("replayPcapBtn").addEventListener("click", () => replayPcap().catch((err) => setStatus(err.message)));
    el("attackType").addEventListener("change", updateAttackHint);
    el("pcapFile").addEventListener("change", updatePcapHint);
    el("iface").addEventListener("change", () => {
        syncAttackTargetFromInterface(true);
        updatePcapHint();
    });
    el("targetIp").addEventListener("input", () => {
        const current = el("targetIp").value.trim();
        const resolved = selectedInterfaceIp() || "127.0.0.1";
        el("targetIp").dataset.autoManaged = !current || current === resolved ? "true" : "false";
        syncAttackTargetFromInterface();
    });

    document.querySelectorAll(".tab-btn").forEach((btn) => {
        btn.addEventListener("click", () => activateTab(btn.dataset.tab));
    });

    document.body.addEventListener("click", (event) => {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        if (target.dataset.action && target.dataset.ip) {
            blockOrUnblock(target.dataset.ip, target.dataset.action).catch((err) => setStatus(err.message));
            return;
        }
        if (target.dataset.shortcut === "export-alerts") {
            window.location.href = "/export_csv?filter=alerts";
        } else if (target.dataset.shortcut === "export-high") {
            window.location.href = "/export_csv?filter=high";
        } else if (target.dataset.shortcut === "refresh") {
            refreshDashboard().catch((err) => setStatus(err.message));
        }
    });
}

async function boot() {
    bindEvents();
    await Promise.all([loadInterfaces(), loadAttackCatalog(), loadPcapCatalog(), refreshPrevention(), refreshHealing()]);
    await refreshDashboard();
    pollHandle = window.setInterval(() => {
        refreshDashboard().catch((err) => setStatus(err.message));
    }, 3000);
}

window.addEventListener("load", () => {
    boot().catch((err) => setStatus(err.message));
});
