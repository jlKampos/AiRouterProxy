// Set up event handlers
const reconnectModal = document.getElementById("components-reconnect-modal");
reconnectModal.addEventListener("components-reconnect-state-changed", handleReconnectStateChanged);

const retryButton = document.getElementById("components-reconnect-button");
retryButton.addEventListener("click", retry);

const resumeButton = document.getElementById("components-resume-button");
resumeButton.addEventListener("click", resume);

// After a definitive failure the circuit is gone: give the user a short window to press
// Retry, then reload instead of leaving the dialog stuck forever (F5 by hand).
const AUTO_RELOAD_MS = 10000;
// Reload cap: a circuit that dies right after every load would otherwise loop forever
// ("loads, dies, reloads..."). Three reloads inside a minute, then stop reloading and leave
// the decision to the user (the Retry button stays available).
const AUTO_RELOAD_MAX = 3;
const RELOAD_WINDOW_MS = 60000;
const RELOAD_STATE_KEY = "airproxy-reconnect-reloads";

let autoReloadHandle = null;

function scheduleAutoReload() {
    cancelAutoReload();
    autoReloadHandle = setTimeout(() => reloadWithCap(), AUTO_RELOAD_MS);
}

function cancelAutoReload() {
    if (autoReloadHandle !== null) {
        clearTimeout(autoReloadHandle);
        autoReloadHandle = null;
    }
}

function reloadWithCap() {
    let count = 0;
    let ts = 0;
    try {
        const raw = sessionStorage.getItem(RELOAD_STATE_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            // Number() coercion, no bitwise ops: int32 coercion truncated Date.now() (~1.8e12),
            // which reset the counter on every call and defeated the reload cap.
            count = Number(parsed.count);
            ts = Number(parsed.ts);
            if (!Number.isFinite(count)) { count = 0; }
            if (!Number.isFinite(ts)) { ts = 0; }
        }
    } catch { /* storage unavailable: fall through with count 0 */ }

    // A reload more than a minute ago is a different incident: start counting again.
    if (Date.now() - ts > RELOAD_WINDOW_MS) { count = 0; }

    if (count >= AUTO_RELOAD_MAX) {
        // Stop reloading and leave the Retry button to the user.
        return false;
    }

    try { sessionStorage.setItem(RELOAD_STATE_KEY, JSON.stringify({ count: count + 1, ts: Date.now() })); } catch { }
    location.reload();
    return true;
}

function handleReconnectStateChanged(event) {
    if (event.detail.state === "show") {
        reconnectModal.showModal();
    } else if (event.detail.state === "hide") {
        cancelAutoReload();
        document.removeEventListener("visibilitychange", retryWhenDocumentBecomesVisible);
        reconnectModal.close();
    } else if (event.detail.state === "failed") {
        scheduleAutoReload();
        document.addEventListener("visibilitychange", retryWhenDocumentBecomesVisible);
    } else if (event.detail.state === "rejected") {
        reloadWithCap();
    }
}

async function retry() {
    cancelAutoReload();
    document.removeEventListener("visibilitychange", retryWhenDocumentBecomesVisible);

    try {
        const successful = await Blazor.reconnect();
        if (!successful) {
            const resumed = await tryResumeCircuit();
            if (!resumed) {
                reloadWithCap();
            } else {
                reconnectModal.close();
            }
        }
    } catch (err) {
        // Server unreachable: try again when the tab becomes visible, but never hang.
        scheduleAutoReload();
        document.addEventListener("visibilitychange", retryWhenDocumentBecomesVisible);
    }
}

async function tryResumeCircuit() {
    // resumeCircuit only exists when circuit pause/resume is supported; a missing or
    // throwing implementation must not block the reload fallback.
    if (typeof Blazor === "undefined" || typeof Blazor.resumeCircuit !== "function") {
        return false;
    }
    try {
        return await Blazor.resumeCircuit();
    } catch {
        return false;
    }
}

async function resume() {
    cancelAutoReload();
    document.removeEventListener("visibilitychange", retryWhenDocumentBecomesVisible);

    const resumed = await tryResumeCircuit();
    if (!resumed) {
        reloadWithCap();
    }
}

async function retryWhenDocumentBecomesVisible() {
    if (document.visibilityState === "visible") {
        await retry();
    }
}
