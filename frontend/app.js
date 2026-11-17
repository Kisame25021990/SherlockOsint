const state = {
  modules: [],
  selected: new Set(["username"]),
  source: null,
  scan: null,
  results: new Map(),
  groups: new Map(),
  startedAt: null,
  markers: new Map(),
  map: null,
  markerLayer: null,
};

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch (_) {
      /* réponse non JSON */
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return response.json();
}

function safeHref(value) {
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? url.href : null;
  } catch (_) {
    return null;
  }
}

function collectMarker(finding) {
  const data = finding.data || {};
  const latitude = Number(data.latitude);
  const longitude = Number(data.longitude);
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return;
  const key = `${finding.module}:${data.ip || ""}:${latitude}:${longitude}`;
  if (state.markers.has(key)) return;
  state.markers.set(key, {
    latitude,
    longitude,
    label: finding.value || `${latitude}, ${longitude}`,
    detail: finding.detail || "",
    url: finding.url || null,
  });
  updateMap();
}

function updateMap() {
  const panel = $("map-panel");
  if (!state.markers.size) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  const points = [...state.markers.values()];

  if (!window.L) {
    $("map").hidden = true;
    const fallback = $("map-fallback");
    fallback.hidden = false;
    fallback.replaceChildren();
    points.forEach((point) => {
      fallback.append(
        el(
          "div",
          "map-fallback-line",
          `${point.label} — ${point.latitude}, ${point.longitude}`,
        ),
      );
    });
    return;
  }

  $("map").hidden = false;
  $("map-fallback").hidden = true;
  if (!state.map) {
    state.map = L.map("map", { scrollWheelZoom: false }).setView(
      [points[0].latitude, points[0].longitude],
      4,
    );
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
      subdomains: "abcd",
      maxZoom: 19,
    }).addTo(state.map);
    state.markerLayer = L.layerGroup().addTo(state.map);
  }

  state.markerLayer.clearLayers();
  points.forEach((point) => {
    const marker = L.marker([point.latitude, point.longitude]).addTo(state.markerLayer);
    const popup = el("div");
    popup.append(el("strong", "", point.label));
    popup.append(el("div", "", `${point.latitude}, ${point.longitude}`));
    if (point.detail) popup.append(el("div", "", point.detail));
    if (point.url) {
      const link = el("a", "", "Ouvrir sur la carte");
      link.href = safeHref(point.url) || "#";
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      popup.append(link);
    }
    marker.bindPopup(popup);
  });

  if (points.length > 1) {
    state.map.fitBounds(L.latLngBounds(points.map((point) => [point.latitude, point.longitude])).pad(0.3));
  } else {
    state.map.setView([points[0].latitude, points[0].longitude], 10);
  }
  setTimeout(() => state.map.invalidateSize(), 50);
}

function resetMap() {
  state.markers.clear();
  if (state.markerLayer) state.markerLayer.clearLayers();
  $("map-panel").hidden = true;
}

function setStatus(text, kind = "muted") {
  const badge = $("scan-state");
  badge.textContent = text;
  badge.className = `badge badge-${kind}`;
}

function setLoading(loading) {
  const button = $("submit-btn");
  button.disabled = loading;
  button.classList.toggle("loading", loading);
  button.querySelector(".button-label").textContent = loading
    ? "Analyse en cours..."
    : "Lancer l'analyse";
}

async function loadModules() {
  state.modules = await api("/api/modules");
  renderModules();
  updatePlaceholder();
}

function renderModules() {
  const container = $("module-list");
  container.replaceChildren();
  state.modules.forEach((module) => {
    const card = el("label", "module-card");
    if (state.selected.has(module.name)) card.classList.add("selected");

    const checkbox = el("input");
    checkbox.type = "checkbox";
    checkbox.checked = state.selected.has(module.name);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) state.selected.add(module.name);
      else state.selected.delete(module.name);
      card.classList.toggle("selected", checkbox.checked);
      updatePlaceholder();
    });

    const text = el("div");
    text.append(el("strong", "", module.label));
    text.append(el("small", "", module.description));
    card.append(checkbox, text);
    container.append(card);
  });
}

function updatePlaceholder() {
  const first = state.modules.find((module) => state.selected.has(module.name));
  $("target").placeholder = first ? first.hint : "ex: alice_dev";
}

function resetResults(scan) {
  if (state.source) state.source.close();
  state.scan = scan;
  state.startedAt = Date.now();
  state.results = new Map(
    scan.modules.map((name) => {
      const info = state.modules.find((module) => module.name === name);
      return [
        name,
        {
          label: info ? info.label : name,
          status: "pending",
          findings: [],
          current: 0,
          total: null,
        },
      ];
    }),
  );
  state.groups = new Map();
  $("findings").replaceChildren();
  resetMap();
  $("scan-target").textContent = scan.target;
  $("scan-id").textContent = scan.id;
  renderModuleStatus();
  renderProgress();
}

function applyScan(scan) {
  state.scan = scan;
  $("scan-target").textContent = scan.target;
  $("scan-id").textContent = scan.id;
  state.results = new Map(
    scan.modules.map((name) => {
      const info = state.modules.find((module) => module.name === name);
      const stored = scan.results.find((result) => result.module === name);
      return [
        name,
        {
          label: info ? info.label : name,
          status: stored ? stored.status : "pending",
          findings: stored ? stored.findings : [],
          current: 0,
          total: null,
          error: stored ? stored.error : null,
        },
      ];
    }),
  );
  state.groups = new Map();
  $("findings").replaceChildren();
  resetMap();
  scan.results.forEach((result) => {
    state.results.set(result.module, {
      label: state.results.get(result.module)?.label || result.module,
      status: result.status,
      findings: result.findings,
      current: result.findings.length,
      total: result.findings.length,
      error: result.error,
    });
  });
  state.results.forEach((result, name) => {
    result.findings.forEach((finding) => appendFinding(finding, name, false));
  });
  renderModuleStatus();
  renderProgress();
}

function renderModuleStatus() {
  const container = $("module-status");
  container.replaceChildren();
  state.results.forEach((result, name) => {
    const chip = el("span", `module-chip ${result.status}`, `${result.label}`);
    chip.dataset.module = name;
    container.append(chip);
  });
}

function setModuleStatus(name, status) {
  const result = state.results.get(name);
  if (result) result.status = status;
  const chip = $("module-status").querySelector(`[data-module="${name}"]`);
  if (chip) chip.className = `module-chip ${status}`;
}

function renderProgress() {
  const ratios = [...state.results.values()].map((result) => {
    if (result.status === "done") return 1;
    if (result.total) return Math.min(1, (result.current || 0) / result.total);
    return 0;
  });
  const percent = ratios.length
    ? Math.round((ratios.reduce((sum, value) => sum + value, 0) / ratios.length) * 100)
    : 0;
  $("progress-bar").style.width = `${percent}%`;
  $("progress-label").textContent = `${percent}%`;
}

function ensureGroup(name) {
  let group = state.groups.get(name);
  if (group) return group;

  const result = state.results.get(name);
  const wrapper = el("div", "finding-group");
  const head = el("div", "finding-group-head");
  head.append(el("span", "", result ? result.label : name));
  head.append(el("span", "count", "0 résultat"));
  const list = el("div", "finding-list");
  wrapper.append(head, list);
  $("findings").append(wrapper);

  group = { wrapper, head, list };
  state.groups.set(name, group);
  return group;
}

function findingNode(finding) {
  const row = el("div", `finding status-${finding.status}`);
  row.append(el("span", "finding-dot"));
  const body = el("div");
  body.append(el("div", "finding-label", finding.label));

  if (finding.value) {
    const value = el("div", "finding-value");
    const href = safeHref(finding.url || finding.value);
    if (href) {
      const link = el("a", "", finding.value);
      link.href = href;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      value.append(link);
    } else {
      value.textContent = finding.value;
    }
    body.append(value);
  }
  if (finding.detail) body.append(el("div", "finding-detail", finding.detail));
  row.append(body);
  return row;
}

function appendFinding(finding, name, scroll = true) {
  collectMarker(finding);
  const group = ensureGroup(name);
  group.list.append(findingNode(finding));
  const count = group.list.children.length;
  group.head.querySelector(".count").textContent =
    `${count} résultat${count > 1 ? "s" : ""}`;
  if (scroll) group.list.lastElementChild.scrollIntoView({ block: "nearest" });
}

function openStream(scanId) {
  if (state.source) state.source.close();
  const source = new EventSource(`/api/scans/${scanId}/stream`);
  state.source = source;
  setStatus("En cours", "running");

  source.addEventListener("scan_start", () => setStatus("En cours", "running"));
  source.addEventListener("module_start", (event) => {
    setModuleStatus(JSON.parse(event.data).module, "running");
    renderProgress();
  });
  source.addEventListener("progress", (event) => {
    const data = JSON.parse(event.data);
    const result = state.results.get(data.module);
    if (result) {
      result.current = data.current;
      result.total = data.total;
    }
    renderProgress();
  });
  source.addEventListener("finding", (event) => {
    const finding = JSON.parse(event.data);
    const result = state.results.get(finding.module);
    if (result) result.findings.push(finding);
    appendFinding(finding, finding.module);
  });
  source.addEventListener("module_done", (event) => {
    const data = JSON.parse(event.data);
    const result = state.results.get(data.module);
    if (result) {
      result.status = data.status;
      result.current = data.total || 1;
      result.total = data.total || 1;
    }
    setModuleStatus(data.module, data.status);
    renderProgress();
  });
  source.addEventListener("module_error", (event) => {
    const data = JSON.parse(event.data);
    setModuleStatus(data.module, "error");
    appendFinding(
      {
        module: data.module,
        label: "Erreur du module",
        value: data.message,
        status: "error",
      },
      data.module,
    );
  });
  source.addEventListener("scan_done", (event) => {
    const status = JSON.parse(event.data).status;
    setStatus(status === "done" ? "Terminé" : "Terminé avec erreurs", status);
    source.close();
    if (state.source === source) state.source = null;
    loadHistory();
  });
}

async function startScan(event) {
  event.preventDefault();
  const target = $("target").value.trim();
  if (!target || state.selected.size === 0) return;

  const payload = {
    target,
    modules: [...state.selected],
    options: {
      timeout: $("timeout").value ? Number($("timeout").value) : null,
      sites: $("sites")
        .value.split(",")
        .map((site) => site.trim())
        .filter(Boolean),
      include_nsfw: $("nsfw").checked,
      proxy: $("proxy").value.trim() || null,
    },
  };

  setLoading(true);
  try {
    const scan = await api("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    resetResults(scan);
    openStream(scan.id);
    loadHistory();
  } catch (error) {
    setStatus("Erreur", "error");
    $("scan-target").textContent = error.message;
  } finally {
    setLoading(false);
  }
}

async function loadScan(scanId) {
  try {
    const scan = await api(`/api/scans/${scanId}`);
    if (state.source) state.source.close();
    state.source = null;
    applyScan(scan);
    setStatus(scan.status === "done" ? "Terminé" : scan.status, scan.status);
  } catch (error) {
    setStatus("Erreur", "error");
    $("scan-target").textContent = error.message;
  }
}

function renderHistory(scans) {
  const container = $("history");
  container.replaceChildren();
  if (!scans.length) {
    container.append(el("p", "empty-history", "Aucune analyse enregistrée."));
    return;
  }
  scans.forEach((scan) => {
    const row = el("div", "history-row");
    const left = el("div");
    left.append(el("div", "history-target", scan.target));
    left.append(
      el(
        "div",
        "history-modules",
        `${scan.modules.join(", ")} · ${scan.results_count} résultat(s)`,
      ),
    );
    const badge = el("span", `badge badge-${scan.status}`, scan.status);
    const date = el(
      "div",
      "history-date",
      new Date(scan.created_at).toLocaleString("fr-FR"),
    );
    const actions = el("div", "history-actions");

    const open = el("button", "", "Ouvrir");
    open.type = "button";
    open.addEventListener("click", () => loadScan(scan.id));

    const json = el("button", "", "JSON");
    json.type = "button";
    json.addEventListener(
      "click",
      () => (window.location.href = `/api/scans/${scan.id}/export?format=json`),
    );

    const csv = el("button", "", "CSV");
    csv.type = "button";
    csv.addEventListener(
      "click",
      () => (window.location.href = `/api/scans/${scan.id}/export?format=csv`),
    );

    const remove = el("button", "danger", "Supprimer");
    remove.type = "button";
    remove.addEventListener("click", async () => {
      await api(`/api/scans/${scan.id}`, { method: "DELETE" });
      loadHistory();
    });

    actions.append(open, json, csv, remove);
    row.append(left, badge, date, actions);
    container.append(row);
  });
}

async function loadHistory() {
  try {
    renderHistory(await api("/api/scans"));
  } catch (_) {
    $("history").replaceChildren(
      el("p", "empty-history", "Historique indisponible."),
    );
  }
}

async function init() {
  try {
    await api("/api/health");
    $("api-status").textContent = "API connectée";
    $("api-status").className = "badge badge-done";
  } catch (_) {
    $("api-status").textContent = "API indisponible";
    $("api-status").className = "badge badge-error";
  }
  await loadModules();
  await loadHistory();
}

$("scan-form").addEventListener("submit", startScan);
$("refresh-history").addEventListener("click", loadHistory);
init();
