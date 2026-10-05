const folderInput = document.querySelector("#folderInput");
const startButton = document.querySelector("#startButton");
const usageButton = document.querySelector("#usageButton");
const selection = document.querySelector("#selection");
const eta = document.querySelector("#eta");
const queue = document.querySelector("#queue");
const counter = document.querySelector("#counter");
const progressBar = document.querySelector("#progressBar");
const processState = document.querySelector("#processState");
const usage = document.querySelector("#usage");
const history = document.querySelector("#history");
const refreshHistory = document.querySelector("#refreshHistory");
let files = [];

function formatMinutes(minutes) {
  if (minutes === 0) return "menos de 1 minuto";
  return `${minutes} minuto${minutes === 1 ? "" : "s"}`;
}

function updateEta(completed = 0, running = false) {
  if (!files.length) {
    eta.textContent = "Tiempo mínimo: —";
    return;
  }
  const remaining = files.length - completed;
  const minutes = running
    ? Math.ceil(remaining / 4)
    : Math.max(0, Math.ceil(files.length / 4) - 1);
  eta.textContent = running
    ? `Tiempo mínimo restante (esperas entre lotes): ${formatMinutes(minutes)}.`
    : `Tiempo mínimo: ${formatMinutes(minutes)} de espera entre lotes (más el tiempo de subida).`;
}

folderInput.addEventListener("change", () => {
  files = [...folderInput.files].filter((file) => file.size <= 650 * 1024 * 1024);
  selection.textContent = files.length
    ? `${files.length} archivo${files.length === 1 ? "" : "s"} listo${files.length === 1 ? "" : "s"} para analizar.`
    : "La carpeta no contiene archivos válidos (máximo 650 MB por archivo).";
  selection.classList.toggle("muted", !files.length);
  startButton.disabled = !files.length;
  updateEta();
  renderQueue();
});
function renderQueue() {
  queue.classList.toggle("empty", !files.length);
  queue.innerHTML = files.length ? files.map((file, i) =>
    `<div class="file-row"><span class="file-name">${i + 1}. ${escapeHtml(file.webkitRelativePath || file.name)}</span><span id="status-${i}" class="status">En espera</span></div>`
  ).join("") : "Selecciona una carpeta para ver sus archivos.";
  counter.textContent = `0 / ${files.length}`;
  progressBar.style.width = "0%";
}
const escapeHtml = (value) => value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]));
const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
async function scanFile(file, index) {
  const status = document.querySelector(`#status-${index}`);
  status.textContent = "Enviando…"; status.className = "status active";
  const form = new FormData(); form.append("file", file, file.name);
  const response = await fetch("/api/scan", { method: "POST", body: form });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Error desconocido");
  status.innerHTML = `<a href="${result.analysisUrl}" target="_blank" rel="noopener">Subido; esperando resultado ↗</a>`;
  status.className = "status ok";
}
startButton.addEventListener("click", async () => {
  startButton.disabled = true;
  processState.textContent = "Enviando archivos…";
  processState.className = "process-state active";
  let completed = 0;
  updateEta(completed, true);
  for (let offset = 0; offset < files.length; offset += 4) {
    const batch = files.slice(offset, offset + 4);
    await Promise.all(batch.map(async (file, position) => {
      const index = offset + position;
      try { await scanFile(file, index); } catch (error) {
        const status = document.querySelector(`#status-${index}`);
        status.textContent = error.message; status.className = "status error";
      } finally {
        completed += 1;
        counter.textContent = `${completed} / ${files.length}`;
        progressBar.style.width = `${(completed / files.length) * 100}%`;
      }
    }));
    updateEta(completed, true);
    if (offset + batch.length < files.length) await wait(60000);
  }
  startButton.textContent = "Análisis terminado";
  processState.textContent = "Envíos completados; esperando resultados";
  processState.className = "process-state";
  eta.textContent = "Análisis terminado.";
  loadHistory();
});
usageButton.addEventListener("click", async () => {
  usageButton.disabled = true; usage.textContent = "Consultando uso…"; usage.classList.remove("hidden");
  try {
    const response = await fetch("/api/usage");
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    const quotas = result.quotas;
    const quota = (name) => quotas[name] || quotas[`api_requests_${name}`] || {};
    usage.innerHTML = `<strong>Uso de API</strong><small>Usuario: ${escapeHtml(result.userId || "desconocido")}</small><div class="usage-grid">
      <div><strong>${quota("minute").used ?? "—"} / ${quota("minute").allowed ?? "—"}</strong><small>Por minuto</small></div>
      <div><strong>${quota("daily").used ?? "—"} / ${quota("daily").allowed ?? "—"}</strong><small>Diario</small></div>
      <div><strong>${quota("monthly").used ?? "—"} / ${quota("monthly").allowed ?? "—"}</strong><small>Mensual</small></div></div>`;
  } catch (error) { usage.textContent = error.message; }
  usageButton.disabled = false;
});

function formatStatus(scan) {
  if (scan.status === "completed") return "Completado";
  if (scan.status === "failed") return "Error";
  if (scan.status === "in-progress") return "En análisis";
  return "En cola";
}

function renderHistory(scans) {
  history.classList.toggle("empty", !scans.length);
  history.innerHTML = scans.length ? scans.map((scan) => {
    const stats = scan.stats || {};
    const detections = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    return `<div class="history-row">
      <div class="history-main"><strong>${escapeHtml(scan.file_name)}</strong>
        <small>${new Date(scan.created_at).toLocaleString()}</small></div>
      <div class="history-result"><span class="history-status status-${escapeHtml(scan.status)}">${formatStatus(scan)}</span>
        <small>${detections} detección${detections === 1 ? "" : "es"} · ${suspicious} sospechoso${suspicious === 1 ? "" : "s"}</small></div>
      <a href="https://www.virustotal.com/gui/file-analysis/${encodeURIComponent(scan.analysis_id)}" target="_blank" rel="noopener">Ver ↗</a>
    </div>`;
  }).join("") : "Todavía no hay análisis registrados.";
}

async function loadHistory() {
  try {
    const response = await fetch("/api/history");
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "No se pudo cargar el historial.");
    renderHistory(result.scans);
    const hasPending = result.scans.some((scan) => !["completed", "failed"].includes(scan.status));
    if (hasPending) {
      processState.textContent = "Consultando resultados…";
      processState.className = "process-state active";
    } else if (scans.length) {
      processState.textContent = "Sin procesos pendientes";
      processState.className = "process-state";
    }
  } catch (error) {
    history.textContent = error.message;
    history.classList.add("empty");
  }
}

refreshHistory.addEventListener("click", loadHistory);
loadHistory();
setInterval(loadHistory, 15000);
