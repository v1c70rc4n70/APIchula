/* PurpleTeam KeyVault — Frontend App Logic */

const state = {
  items: [],
  stats: null,
  revealedCache: {},
  filters: {
    search: "",
    health: "all",
    environment: "",
    project: "",
    category: "",
    provider: "",
  },
};

const PROVIDER_PRESETS = {
  supabase: {
    provider: "Supabase",
    category: "Base de Datos",
    env_var_name: "SUPABASE_SERVICE_ROLE_KEY",
    base_url: "https://api.supabase.com/v1",
    docs_url: "https://supabase.com/dashboard/account/tokens",
    check_url: "https://api.supabase.com/v1/projects",
    check_header_name: "Authorization",
    check_header_prefix: "Bearer ",
  },
  openai: {
    provider: "OpenAI",
    category: "AI / LLM",
    env_var_name: "OPENAI_API_KEY",
    base_url: "https://api.openai.com/v1",
    docs_url: "https://platform.openai.com/api-keys",
    check_url: "https://api.openai.com/v1/models",
    check_header_name: "Authorization",
    check_header_prefix: "Bearer ",
  },
  anthropic: {
    provider: "Anthropic",
    category: "AI / LLM",
    env_var_name: "ANTHROPIC_API_KEY",
    base_url: "https://api.anthropic.com/v1",
    docs_url: "https://console.anthropic.com/settings/keys",
    check_url: "https://api.anthropic.com/v1/models",
    check_header_name: "x-api-key",
    check_header_prefix: "",
  },
  github: {
    provider: "GitHub",
    category: "DevOps / Git",
    env_var_name: "GITHUB_TOKEN",
    base_url: "https://api.github.com",
    docs_url: "https://github.com/settings/tokens",
    check_url: "https://api.github.com/user",
    check_header_name: "Authorization",
    check_header_prefix: "Bearer ",
  },
  shodan: {
    provider: "Shodan",
    category: "OSINT / Sec",
    env_var_name: "SHODAN_API_KEY",
    base_url: "https://api.shodan.io",
    docs_url: "https://account.shodan.io/",
    check_url: "",
    check_header_name: "Authorization",
    check_header_prefix: "Bearer ",
  },
  virustotal: {
    provider: "VirusTotal",
    category: "OSINT / Sec",
    env_var_name: "VT_API_KEY",
    base_url: "https://www.virustotal.com/api/v3",
    docs_url: "https://www.virustotal.com/gui/my-apikey",
    check_url: "https://www.virustotal.com/api/v3/domains/virustotal.com",
    check_header_name: "x-apikey",
    check_header_prefix: "",
  },
  cloudflare: {
    provider: "Cloudflare",
    category: "Cloud / Infra",
    env_var_name: "CLOUDFLARE_API_TOKEN",
    base_url: "https://api.cloudflare.com/client/v4",
    docs_url: "https://dash.cloudflare.com/profile/api-tokens",
    check_url: "https://api.cloudflare.com/client/v4/user/tokens/verify",
    check_header_name: "Authorization",
    check_header_prefix: "Bearer ",
  },
  aws: {
    provider: "AWS",
    category: "Cloud / Infra",
    env_var_name: "AWS_ACCESS_KEY_ID",
    base_url: "https://amazonaws.com",
    docs_url: "https://console.aws.amazon.com/iam/",
    check_url: "",
    check_header_name: "Authorization",
    check_header_prefix: "Bearer ",
  },
  stripe: {
    provider: "Stripe",
    category: "Pagos / SaaS",
    env_var_name: "STRIPE_SECRET_KEY",
    base_url: "https://api.stripe.com/v1",
    docs_url: "https://dashboard.stripe.com/apikeys",
    check_url: "https://api.stripe.com/v1/balance",
    check_header_name: "Authorization",
    check_header_prefix: "Bearer ",
  },
};

function showToast(msg) {
  const container = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

async function apiFetch(url, options = {}) {
  const opts = {
    headers: { "Content-Type": "application/json" },
    ...options,
  };
  if (opts.body && typeof opts.body !== "string") {
    opts.body = JSON.stringify(opts.body);
  }
  const resp = await fetch(url, opts);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok || data.ok === false) {
    throw new Error(data.error || `Error HTTP ${resp.status}`);
  }
  return data;
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatDate(iso) {
  if (!iso) return "—";
  return iso.slice(0, 10);
}

function healthLabel(item) {
  switch (item.computed_health) {
    case "healthy":
      return { text: "✓ Saludable", cls: "health-healthy" };
    case "expiring_soon":
      return { text: `⚠️ Expira en ${item.days_until_expiry}d`, cls: "health-expiring_soon" };
    case "expired":
      return { text: "❌ Expirada", cls: "health-expired" };
    case "rotation_due":
      return { text: `🔄 Rotar (${item.days_since_rotation}d)`, cls: "health-rotation_due" };
    case "revoked":
      return { text: "🕰️ Antigua / Inactiva", cls: "health-revoked" };
    default:
      return { text: item.status, cls: "health-healthy" };
  }
}

async function checkVaultStatus() {
  const res = await fetch("/api/status");
  const status = await res.json();
  document.getElementById("db-path-label").textContent = `DB: ${status.db_path}`;

  const authScreen = document.getElementById("auth-screen");
  const setupForm = document.getElementById("setup-form");
  const unlockForm = document.getElementById("unlock-form");
  const appShell = document.getElementById("app-shell");

  if (!status.initialized) {
    authScreen.classList.remove("hidden");
    setupForm.classList.remove("hidden");
    unlockForm.classList.add("hidden");
    appShell.classList.add("hidden");
  } else if (!status.unlocked) {
    authScreen.classList.remove("hidden");
    setupForm.classList.add("hidden");
    unlockForm.classList.remove("hidden");
    appShell.classList.add("hidden");
    document.getElementById("unlock-password").focus();
  } else {
    authScreen.classList.add("hidden");
    appShell.classList.remove("hidden");
    await loadKeys();
  }
}

async function loadKeys() {
  try {
    let data = await apiFetch("/api/keys");
    if (!state.initialScanDone) {
      state.initialScanDone = true;
      await apiFetch("/api/integrations/auto-import", { method: "POST" }).catch(() => {});
      data = await apiFetch("/api/keys");
    }
    state.items = data.items || [];
    state.stats = data.stats || {};
    renderStatsAndFilters();
    renderKeysList();
  } catch (err) {
    showToast(err.message);
  }
}

function renderStatsAndFilters() {
  const s = state.stats || {};
  document.getElementById("stat-total").textContent = s.total ?? 0;
  document.getElementById("stat-healthy").textContent = s.healthy ?? 0;
  document.getElementById("stat-expiring").textContent = (s.expiring_soon ?? 0) + (s.expired ?? 0);
  document.getElementById("stat-rotation").textContent = s.rotation_due ?? 0;

  document.getElementById("count-all").textContent = s.total ?? 0;
  document.getElementById("count-alerts").textContent = s.alerts_count ?? 0;
  document.getElementById("count-rotation").textContent = s.rotation_due ?? 0;
  const revEl = document.getElementById("count-revoked");
  if (revEl) revEl.textContent = s.revoked ?? 0;

  // Proyectos en el sidebar
  const projContainer = document.getElementById("project-filter-list");
  const projects = s.projects || [];
  projContainer.innerHTML = [
    `<button class="nav-item ${state.filters.project === "" ? "active" : ""}" data-project=""><span>Todos los proyectos</span></button>`,
    ...projects.map(
      (p) =>
        `<button class="nav-item ${state.filters.project === p ? "active" : ""}" data-project="${escapeHtml(p)}"><span>📁 ${escapeHtml(p)}</span></button>`
    ),
  ].join("");

  projContainer.querySelectorAll("[data-project]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.filters.project = btn.dataset.project;
      renderStatsAndFilters();
      renderKeysList();
    });
  });

  // Categorías en el sidebar
  const catContainer = document.getElementById("category-filter-list");
  const categories = s.categories || [];
  catContainer.innerHTML = [
    `<button class="nav-item ${state.filters.category === "" ? "active" : ""}" data-category=""><span>Todas las categorías</span></button>`,
    ...categories.map(
      (c) =>
        `<button class="nav-item ${state.filters.category === c ? "active" : ""}" data-category="${escapeHtml(c)}"><span>🏷️ ${escapeHtml(c)}</span></button>`
    ),
  ].join("");

  catContainer.querySelectorAll("[data-category]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.filters.category = btn.dataset.category;
      renderStatsAndFilters();
      renderKeysList();
    });
  });

  // Selector de proveedores
  const provSelect = document.getElementById("provider-select");
  const currentProv = state.filters.provider;
  const providers = s.providers || [];
  provSelect.innerHTML =
    `<option value="">Todos los proveedores</option>` +
    providers
      .map(
        (p) =>
          `<option value="${escapeHtml(p)}" ${currentProv === p ? "selected" : ""}>${escapeHtml(p)}</option>`
      )
      .join("");

  // También poblar el selector del modal de exportación y sincronización
  const expProj = document.getElementById("exp-project");
  expProj.innerHTML =
    `<option value="">Todos los proyectos</option>` +
    projects.map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join("");

  const syncProj = document.getElementById("sync-project");
  if (syncProj) {
    syncProj.innerHTML =
      `<option value="">Todos los proyectos</option>` +
      projects.map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join("");
  }
}

function getFilteredKeys() {
  const f = state.filters;
  const q = f.search.trim().toLowerCase();

  return state.items.filter((item) => {
    if (f.health === "favorites" && !item.is_favorite) return false;
    if (
      f.health === "alerts" &&
      !["expiring_soon", "expired", "rotation_due"].includes(item.computed_health)
    )
      return false;
    if (f.health === "rotation_due" && item.computed_health !== "rotation_due") return false;
    if (f.health === "revoked" && item.status !== "revoked") return false;

    if (f.environment && item.environment !== f.environment) return false;
    if (f.project && item.project !== f.project) return false;
    if (f.category && item.category !== f.category) return false;
    if (f.provider && item.provider !== f.provider) return false;

    if (q) {
      const hay = [
        item.name,
        item.provider,
        item.category,
        item.project,
        item.environment,
        item.env_var_name,
        item.notes,
        ...(item.tags || []),
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderKeysList() {
  const container = document.getElementById("keys-container");
  const filtered = getFilteredKeys();
  document.getElementById("results-counter").textContent = `${filtered.length} clave(s) mostrada(s)`;

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>No hay API Keys que coincidan con el filtro actual</h3>
        <p style="margin-top:6px;">Pulsa en <strong>+ Nueva API Key</strong> o <strong>📥 Importar .env</strong> para añadir tus credenciales cifradas.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = filtered
    .map((item) => {
      const h = healthLabel(item);
      const revealed = state.revealedCache[item.id];
      const secretDisplay = revealed ? escapeHtml(revealed) : escapeHtml(item.key_hint);
      const envBadgeClass = `badge-env-${escapeHtml(item.environment)}`;

      const checkBadge = item.last_check_status
        ? `<span class="tag-item" title="Última verificación: ${escapeHtml(item.last_checked_at || "")}">
             HTTP Check: ${item.last_check_status === "valid" ? "🟢 OK" : item.last_check_status === "invalid" ? "🔴 Inválida" : "🟡 " + escapeHtml(item.last_check_status)}
             ${item.last_check_code ? `(${item.last_check_code})` : ""}
           </span>`
        : "";

      return `
        <article class="key-card" data-id="${item.id}">
          <div class="key-card-top">
            <div class="key-title-group">
              <button class="fav-star ${item.is_favorite ? "active" : ""}" data-action="toggle-fav" data-id="${item.id}" title="Marcar favorita">★</button>
              <span class="provider-pill">${escapeHtml(item.provider)}</span>
              <span class="key-name">${escapeHtml(item.name)}</span>
              <span class="badge ${envBadgeClass}">${escapeHtml(item.environment)}</span>
              <span class="tag-item">📁 ${escapeHtml(item.project)}</span>
              <span class="tag-item">${escapeHtml(item.category)}</span>
            </div>
            <div class="key-meta-badges">
              ${checkBadge}
              <span class="health-badge ${h.cls}">${h.text}</span>
            </div>
          </div>

          <div class="key-secret-bar">
            <div class="secret-left">
              <span class="env-var-chip" data-action="copy-env-line" data-id="${item.id}" title="Clic para copiar línea KEY=VALUE para .env">
                ${escapeHtml(item.env_var_name || "API_KEY")}
              </span>
              <code class="secret-value">${secretDisplay}</code>
            </div>
            <div class="secret-actions">
              <button class="btn btn-ghost btn-sm" data-action="reveal" data-id="${item.id}">
                ${revealed ? "🙈 Ocultar" : "👁️ Revelar"}
              </button>
              <button class="btn btn-secondary btn-sm" data-action="copy-key" data-id="${item.id}">
                📋 Copiar Key
              </button>
              <button class="btn btn-ghost btn-sm" data-action="copy-env-line" data-id="${item.id}" title="Copiar como VAR=&quot;KEY&quot;">
                .env
              </button>
              <button class="btn btn-cloud-gh btn-sm" data-action="push-one-gh" data-id="${item.id}" title="Enviar esta clave directo a GitHub Secrets">
                🐙 GH
              </button>
              <button class="btn btn-cloud-sb btn-sm" data-action="push-one-sb" data-id="${item.id}" title="Enviar esta clave directo a Supabase Secrets">
                ⚡ SB
              </button>
              <button class="btn btn-cloud-cf btn-sm" data-action="push-one-cf" data-id="${item.id}" title="Enviar esta clave directo a Cloudflare Worker">
                ☁️ CF
              </button>
              ${
                item.check_url
                  ? `<button class="btn btn-ghost btn-sm" data-action="verify" data-id="${item.id}" title="Probar validez contra ${escapeHtml(item.check_url)}">🩺 Probar</button>`
                  : ""
              }
              <button class="btn btn-ghost btn-sm" data-action="rotate" data-id="${item.id}">🔄 Rotar</button>
              <button class="btn btn-ghost btn-sm" data-action="edit" data-id="${item.id}">✏️ Editar</button>
              <button class="btn btn-danger-outline btn-sm" data-action="delete" data-id="${item.id}">🗑️</button>
            </div>
          </div>

          <div class="key-card-bottom">
            <div class="key-tags">
              <span>Rotada: <strong>${formatDate(item.last_rotated_at)}</strong></span>
              <span>•</span>
              <span>Expira: <strong>${item.expires_at ? formatDate(item.expires_at) : "Sin caducidad"}</strong></span>
              ${
                item.docs_url
                  ? `<span>• <a href="${escapeHtml(item.docs_url)}" target="_blank" rel="noopener noreferrer" style="color:var(--accent-hover);">Consola / Docs ↗</a></span>`
                  : ""
              }
              ${
                item.notes
                  ? `<span>• 📝 ${escapeHtml(item.notes.slice(0, 75))}${item.notes.length > 75 ? "…" : ""}</span>`
                  : ""
              }
            </div>
            <div class="key-tags">
              ${(item.tags || []).map((t) => `<span class="tag-item">#${escapeHtml(t)}</span>`).join("")}
            </div>
          </div>
        </article>
      `;
    })
    .join("");
}

async function fetchPlainSecret(keyId) {
  if (state.revealedCache[keyId]) {
    return state.revealedCache[keyId];
  }
  const data = await apiFetch(`/api/keys/${keyId}?reveal=1`);
  return data.item.api_key;
}

async function handleCardAction(e) {
  const btn = e.target.closest("[data-action]");
  if (!btn) return;
  const action = btn.dataset.action;
  const keyId = Number(btn.dataset.id);
  const item = state.items.find((k) => k.id === keyId);
  if (!item) return;

  try {
    if (action === "reveal") {
      if (state.revealedCache[keyId]) {
        delete state.revealedCache[keyId];
      } else {
        state.revealedCache[keyId] = await fetchPlainSecret(keyId);
      }
      renderKeysList();
    } else if (action === "copy-key") {
      const secret = await fetchPlainSecret(keyId);
      await navigator.clipboard.writeText(secret);
      showToast(`✅ API Key de "${item.name}" copiada al portapapeles`);
    } else if (action === "copy-env-line") {
      const secret = await fetchPlainSecret(keyId);
      const line = `${item.env_var_name || "API_KEY"}="${secret.replace(/"/g, '\\"')}"`;
      await navigator.clipboard.writeText(line);
      showToast(`✅ Línea .env (${item.env_var_name}) copiada`);
    } else if (action === "push-one-gh" || action === "push-one-sb" || action === "push-one-cf") {
      const targetMap = {
        "push-one-gh": "github",
        "push-one-sb": "supabase",
        "push-one-cf": "cloudflare",
      };
      const target = targetMap[action];
      showToast(`🚀 Enviando ${item.env_var_name} a ${target.toUpperCase()}...`);
      try {
        const res = await apiFetch(`/api/integrations/sync/${target}`, {
          method: "POST",
          body: { key_ids: [keyId] },
        });
        const pushedCount = (res.result.pushed || []).length;
        if (pushedCount > 0) {
          showToast(`✅ ${item.env_var_name} subida a ${target.toUpperCase()} correctamente`);
        } else {
          showToast(`⚠️ Error subiendo a ${target}: ${(res.result.errors || []).join(", ")}`);
        }
      } catch (err) {
        showToast(`ℹ️ Configura ${target.toUpperCase()} en esta ventana o copia el comando`);
        await openCloudSyncModal(target);
      }
    } else if (action === "toggle-fav") {
      await apiFetch(`/api/keys/${keyId}`, {
        method: "PUT",
        body: { is_favorite: !item.is_favorite },
      });
      await loadKeys();
    } else if (action === "verify") {
      showToast(`Comprobando endpoint de ${item.name}...`);
      const res = await apiFetch(`/api/keys/${keyId}/verify`, { method: "POST" });
      showToast(`Resultado Health Check: ${res.result.message}`);
      await loadKeys();
    } else if (action === "rotate") {
      openRotateModal(item);
    } else if (action === "edit") {
      openKeyModal(item);
    } else if (action === "delete") {
      if (confirm(`¿Eliminar permanentemente la API Key "${item.name}" (${item.provider})?`)) {
        await apiFetch(`/api/keys/${keyId}`, { method: "DELETE" });
        delete state.revealedCache[keyId];
        showToast("🗑️ Clave eliminada de la bóveda");
        await loadKeys();
      }
    }
  } catch (err) {
    showToast(`❌ ${err.message}`);
  }
}

function openKeyModal(item = null) {
  const modal = document.getElementById("key-modal");
  const title = document.getElementById("key-modal-title");
  const form = document.getElementById("key-form");
  form.reset();

  document.getElementById("key-id").value = item ? item.id : "";
  title.textContent = item ? `Editar: ${item.name}` : "Nueva API Key";

  const keyInput = document.getElementById("f-apikey");
  const reqLabel = document.getElementById("f-apikey-req");
  if (item) {
    keyInput.required = false;
    reqLabel.textContent = "(Opcional al editar)";
    document.getElementById("f-name").value = item.name;
    document.getElementById("f-provider").value = item.provider;
    document.getElementById("f-category").value = item.category;
    document.getElementById("f-project").value = item.project;
    document.getElementById("f-environment").value = item.environment;
    document.getElementById("f-env-var").value = item.env_var_name;
    document.getElementById("f-tags").value = (item.tags || []).join(", ");
    document.getElementById("f-expires").value = item.expires_at ? item.expires_at.slice(0, 10) : "";
    document.getElementById("f-rotation-days").value = item.rotation_interval_days ?? 90;
    document.getElementById("f-status").value = item.status || "active";
    document.getElementById("f-base-url").value = item.base_url || "";
    document.getElementById("f-docs-url").value = item.docs_url || "";
    document.getElementById("f-check-url").value = item.check_url || "";
    document.getElementById("f-check-header").value = item.check_header_name || "Authorization";
    document.getElementById("f-check-prefix").value = item.check_header_prefix ?? "Bearer ";
    document.getElementById("f-notes").value = item.notes || "";
    document.getElementById("f-favorite").checked = Boolean(item.is_favorite);
  } else {
    keyInput.required = true;
    reqLabel.textContent = "*";
    document.getElementById("f-project").value = state.filters.project || "default";
  }

  modal.classList.remove("hidden");
}

async function openRotateModal(item) {
  const modal = document.getElementById("rotate-modal");
  document.getElementById("rotate-form").reset();
  document.getElementById("rotate-key-id").value = item.id;
  document.getElementById("rotate-key-label").textContent = `${item.provider} — ${item.name} (${item.project}/${item.environment})`;
  document.getElementById("rotate-expires").value = item.expires_at ? item.expires_at.slice(0, 10) : "";
  modal.classList.remove("hidden");

  const histContainer = document.getElementById("rotation-history-list");
  histContainer.innerHTML = `<span class="muted-text">Cargando historial...</span>`;
  try {
    const data = await apiFetch(`/api/keys/${item.id}/history?reveal=1`);
    const list = data.history || [];
    if (list.length === 0) {
      histContainer.innerHTML = `<span class="muted-text">Sin rotaciones previas registradas.</span>`;
    } else {
      histContainer.innerHTML = list
        .map(
          (h) => `
          <div class="history-item">
            <div>
              <strong>${formatDate(h.rotated_at)}</strong> — <code>${escapeHtml(h.old_key_hint)}</code>
              <div class="muted-text">${escapeHtml(h.reason || "Rotación manual")}</div>
            </div>
            <button type="button" class="btn btn-ghost btn-sm" data-copy-old="${escapeHtml(h.old_api_key || "")}">
              📋 Copiar antigua
            </button>
          </div>
        `
        )
        .join("");
      histContainer.querySelectorAll("[data-copy-old]").forEach((b) => {
        b.addEventListener("click", async () => {
          await navigator.clipboard.writeText(b.dataset.copyOld);
          showToast("Clave anterior copiada al portapapeles");
        });
      });
    }
  } catch (err) {
    histContainer.innerHTML = `<span class="muted-text">${escapeHtml(err.message)}</span>`;
  }
}

async function refreshExportPreview() {
  const fmt = document.getElementById("exp-format").value;
  const proj = document.getElementById("exp-project").value;
  const env = document.getElementById("exp-env").value;
  const params = new URLSearchParams({ format: fmt });
  if (proj) params.set("project", proj);
  if (env) params.set("environment", env);

  try {
    const data = await apiFetch(`/api/export?${params.toString()}`);
    document.getElementById("exp-preview").value = data.content || "";
  } catch (err) {
    showToast(err.message);
  }
}

async function openCloudSyncModal(initialTarget = "github") {
  const modal = document.getElementById("sync-modal");
  modal.classList.remove("hidden");
  document.getElementById("sync-result-banner").classList.add("hidden");

  // Seleccionar pestaña inicial
  const tabMap = {
    github: "tab-github",
    supabase: "tab-supabase",
    cloudflare: "tab-cloudflare",
  };
  const targetPaneId = tabMap[initialTarget] || "tab-github";
  document.querySelectorAll("[data-sync-tab]").forEach((b) => {
    b.classList.toggle("active", b.dataset.syncTab === targetPaneId);
  });
  document.querySelectorAll(".sync-tab-pane").forEach((p) => {
    p.classList.toggle("hidden", p.id !== targetPaneId);
  });

  // Cargar configuración guardada
  try {
    const res = await apiFetch("/api/integrations");
    const c = res.config || {};
    document.getElementById("cfg-gh-repo").value = c.github_repo || "";
    document.getElementById("cfg-gh-env").value = c.github_env || "";
    document.getElementById("cfg-gh-token").value = "";
    document.getElementById("hint-gh-token").textContent = c.has_github_token ? `(Guardado: ${c.github_token_hint})` : "";

    document.getElementById("cfg-sb-ref").value = c.supabase_project_ref || "";
    document.getElementById("cfg-sb-token").value = "";
    document.getElementById("hint-sb-token").textContent = c.has_supabase_token ? `(Guardado: ${c.supabase_token_hint})` : "";

    document.getElementById("cfg-cf-account").value = c.cloudflare_account_id || "";
    document.getElementById("cfg-cf-worker").value = c.cloudflare_worker_name || "";
    document.getElementById("cfg-cf-pages").value = c.cloudflare_pages_project || "";
    document.getElementById("cfg-cf-token").value = "";
    document.getElementById("hint-cf-token").textContent = c.has_cloudflare_token ? `(Guardado: ${c.cloudflare_token_hint})` : "";
  } catch (err) {
    showToast(err.message);
  }

  // Descubrir entorno local (GitHub auth, repos, secretos actuales)
  try {
    const discRes = await apiFetch("/api/integrations/discover");
    const d = discRes.discovery || {};
    const authBadge = document.getElementById("gh-auth-badge");
    if (authBadge) {
      authBadge.textContent = d.gh_auth_user ? `✓ Conectado como @${d.gh_auth_user}` : "No autenticado en gh";
    }
    const dl = document.getElementById("gh-repo-datalist");
    if (dl && Array.isArray(d.gh_repos)) {
      dl.innerHTML = d.gh_repos
        .map((r) => `<option value="${escapeHtml(r.nameWithOwner)}"></option>`)
        .join("");
    }
    const remList = document.getElementById("gh-remote-secrets-list");
    if (remList) {
      const secrets = d.gh_remote_secrets || [];
      remList.innerHTML = secrets.length
        ? secrets
            .map(
              (s) =>
                `<span class="tag-item" title="Actualizado: ${escapeHtml(s.updated_at)}">🔒 ${escapeHtml(s.name)}</span>`
            )
            .join("")
        : `<span class="muted-text">Ninguno o sin acceso al repo seleccionado</span>`;
    }
  } catch (_) {}

  await refreshSyncSnippets();
}

async function refreshSyncSnippets() {
  const proj = document.getElementById("sync-project").value;
  const env = document.getElementById("sync-env").value;
  const params = new URLSearchParams();
  if (proj) params.set("project", proj);
  if (env) params.set("environment", env);

  try {
    const res = await apiFetch(`/api/integrations/snippets?${params.toString()}`);
    const s = res.snippets || {};
    document.getElementById("snip-github").value = s.github_cli || "";
    document.getElementById("snip-supabase-cli").value = s.supabase_cli || "";
    document.getElementById("snip-supabase-sql").value = s.supabase_sql || "";
    document.getElementById("snip-cloudflare").value = s.cloudflare_cli || "";
    document.getElementById("sync-key-count").textContent = `${s.count ?? 0} claves activas`;
  } catch (err) {
    showToast(err.message);
  }
}

async function saveIntegrationSettings() {
  const payload = {
    github_repo: document.getElementById("cfg-gh-repo").value,
    github_env: document.getElementById("cfg-gh-env").value,
    supabase_project_ref: document.getElementById("cfg-sb-ref").value,
    cloudflare_account_id: document.getElementById("cfg-cf-account").value,
    cloudflare_worker_name: document.getElementById("cfg-cf-worker").value,
    cloudflare_pages_project: document.getElementById("cfg-cf-pages").value,
  };
  const ghTok = document.getElementById("cfg-gh-token").value.trim();
  const sbTok = document.getElementById("cfg-sb-token").value.trim();
  const cfTok = document.getElementById("cfg-cf-token").value.trim();
  if (ghTok) payload.github_token = ghTok;
  if (sbTok) payload.supabase_token = sbTok;
  if (cfTok) payload.cloudflare_token = cfTok;

  const res = await apiFetch("/api/integrations", { method: "POST", body: payload });
  const c = res.config || {};
  document.getElementById("cfg-gh-token").value = "";
  document.getElementById("cfg-sb-token").value = "";
  document.getElementById("cfg-cf-token").value = "";
  document.getElementById("hint-gh-token").textContent = c.has_github_token ? `(Guardado: ${c.github_token_hint})` : "";
  document.getElementById("hint-sb-token").textContent = c.has_supabase_token ? `(Guardado: ${c.supabase_token_hint})` : "";
  document.getElementById("hint-cf-token").textContent = c.has_cloudflare_token ? `(Guardado: ${c.cloudflare_token_hint})` : "";
  await refreshSyncSnippets();
}

function bindEvents() {
  // Inicializar bóveda
  document.getElementById("setup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = document.getElementById("setup-password").value;
    const pw2 = document.getElementById("setup-password-confirm").value;
    const errBox = document.getElementById("auth-error");
    errBox.classList.add("hidden");
    if (pw !== pw2) {
      errBox.textContent = "Las contraseñas no coinciden.";
      errBox.classList.remove("hidden");
      return;
    }
    try {
      await apiFetch("/api/setup", { method: "POST", body: { master_password: pw } });
      showToast("🔐 Bóveda inicializada con éxito");
      await checkVaultStatus();
    } catch (err) {
      errBox.textContent = err.message;
      errBox.classList.remove("hidden");
    }
  });

  // Desbloquear bóveda
  document.getElementById("unlock-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = document.getElementById("unlock-password").value;
    const errBox = document.getElementById("auth-error");
    errBox.classList.add("hidden");
    try {
      await apiFetch("/api/unlock", { method: "POST", body: { master_password: pw } });
      document.getElementById("unlock-password").value = "";
      await checkVaultStatus();
    } catch (err) {
      errBox.textContent = err.message;
      errBox.classList.remove("hidden");
    }
  });

  // Bloquear bóveda
  document.getElementById("btn-lock-vault").addEventListener("click", async () => {
    state.revealedCache = {};
    await apiFetch("/api/lock", { method: "POST" });
    await checkVaultStatus();
  });

  // Búsqueda y atajo '/'
  const searchInput = document.getElementById("search-input");
  searchInput.addEventListener("input", () => {
    state.filters.search = searchInput.value;
    renderKeysList();
  });
  window.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") {
      e.preventDefault();
      searchInput.focus();
    }
  });

  // Filtros de salud del sidebar
  document.querySelectorAll("[data-filter-health]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-filter-health]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.filters.health = btn.dataset.filterHealth;
      renderKeysList();
    });
  });

  // Filtros de entorno
  document.querySelectorAll("#env-filter-list .chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      document.querySelectorAll("#env-filter-list .chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      state.filters.environment = chip.dataset.env;
      renderKeysList();
    });
  });

  // Selector proveedor
  document.getElementById("provider-select").addEventListener("change", (e) => {
    state.filters.provider = e.target.value;
    renderKeysList();
  });

  // Delegación de eventos en tarjetas
  document.getElementById("keys-container").addEventListener("click", handleCardAction);

  // Abrir modal nueva clave
  document.getElementById("btn-new-key").addEventListener("click", () => openKeyModal(null));

  // Plantillas rápidas en el modal
  document.querySelectorAll(".chip-preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      const p = PROVIDER_PRESETS[btn.dataset.preset];
      if (!p) return;
      document.getElementById("f-provider").value = p.provider;
      document.getElementById("f-category").value = p.category;
      document.getElementById("f-env-var").value = p.env_var_name;
      document.getElementById("f-base-url").value = p.base_url;
      document.getElementById("f-docs-url").value = p.docs_url;
      document.getElementById("f-check-url").value = p.check_url;
      document.getElementById("f-check-header").value = p.check_header_name;
      document.getElementById("f-check-prefix").value = p.check_header_prefix;
      if (!document.getElementById("f-name").value) {
        document.getElementById("f-name").value = `${p.provider} API Key`;
      }
    });
  });

  // Mostrar/Ocultar input de clave en modal
  document.getElementById("btn-toggle-f-key").addEventListener("click", () => {
    const inp = document.getElementById("f-apikey");
    inp.type = inp.type === "password" ? "text" : "password";
  });

  // Generar token aleatorio
  document.getElementById("btn-gen-random").addEventListener("click", async () => {
    const data = await apiFetch("/api/generate-secret");
    const inp = document.getElementById("f-apikey");
    inp.value = data.secret;
    inp.type = "text";
  });

  // Guardar crear / editar clave
  document.getElementById("key-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const id = document.getElementById("key-id").value;
    const payload = {
      name: document.getElementById("f-name").value,
      provider: document.getElementById("f-provider").value,
      category: document.getElementById("f-category").value,
      project: document.getElementById("f-project").value,
      environment: document.getElementById("f-environment").value,
      api_key: document.getElementById("f-apikey").value,
      env_var_name: document.getElementById("f-env-var").value,
      secondary_secret: document.getElementById("f-secondary").value,
      tags: document.getElementById("f-tags").value,
      expires_at: document.getElementById("f-expires").value,
      rotation_interval_days: Number(document.getElementById("f-rotation-days").value || 90),
      status: document.getElementById("f-status").value,
      base_url: document.getElementById("f-base-url").value,
      docs_url: document.getElementById("f-docs-url").value,
      check_url: document.getElementById("f-check-url").value,
      check_header_name: document.getElementById("f-check-header").value,
      check_header_prefix: document.getElementById("f-check-prefix").value,
      notes: document.getElementById("f-notes").value,
      is_favorite: document.getElementById("f-favorite").checked,
    };
    if (id && !payload.secondary_secret) {
      delete payload.secondary_secret;
    }

    try {
      if (id) {
        await apiFetch(`/api/keys/${id}`, { method: "PUT", body: payload });
        delete state.revealedCache[id];
        showToast("✅ API Key actualizada");
      } else {
        await apiFetch("/api/keys", { method: "POST", body: payload });
        showToast("✅ Nueva API Key cifrada y guardada");
      }
      document.getElementById("key-modal").classList.add("hidden");
      await loadKeys();
    } catch (err) {
      showToast(`❌ ${err.message}`);
    }
  });

  // Formulario rotar clave
  document.getElementById("rotate-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const id = document.getElementById("rotate-key-id").value;
    try {
      await apiFetch(`/api/keys/${id}/rotate`, {
        method: "POST",
        body: {
          new_api_key: document.getElementById("rotate-new-secret").value,
          reason: document.getElementById("rotate-reason").value,
          expires_at: document.getElementById("rotate-expires").value,
        },
      });
      delete state.revealedCache[id];
      document.getElementById("rotate-modal").classList.add("hidden");
      showToast("🔄 Clave rotada y versión anterior archivada");
      await loadKeys();
    } catch (err) {
      showToast(`❌ ${err.message}`);
    }
  });

  // Exportación
  document.getElementById("btn-export-env").addEventListener("click", async () => {
    document.getElementById("export-modal").classList.remove("hidden");
    await refreshExportPreview();
  });

  // Panel de Conexión y Sincronización Nube (GitHub / Supabase / Cloudflare)
  document.getElementById("btn-cloud-sync").addEventListener("click", () => openCloudSyncModal("github"));
  document.getElementById("btn-quick-gh").addEventListener("click", () => openCloudSyncModal("github"));
  document.getElementById("btn-quick-sb").addEventListener("click", () => openCloudSyncModal("supabase"));
  document.getElementById("btn-quick-cf").addEventListener("click", () => openCloudSyncModal("cloudflare"));

  async function runExhaustiveScan() {
    showToast("🔍 Escaneando todo el sistema (activas, nuevas, rotadas y antiguas)...");
    try {
      const res = await apiFetch("/api/integrations/auto-import", { method: "POST" });
      const r = res.result || {};
      const nNew = (r.imported || []).length;
      const nRot = (r.updated_rotated || []).length;
      const nHist = (r.historical_added || []).length;
      const nSrc = r.sources_scanned ?? 0;

      if (nNew + nRot + nHist > 0) {
        showToast(
          `✅ Escaneo (${nSrc} fuentes): +${nNew} nuevas, ${nRot} actualizadas/rotadas, +${nHist} históricas/antiguas`
        );
      } else {
        showToast(`✓ Escaneo completado (${nSrc} fuentes revisadas): todas las claves están al día`);
      }
      await loadKeys();
    } catch (err) {
      showToast(`❌ ${err.message}`);
    }
  }

  document.getElementById("btn-auto-import").addEventListener("click", runExhaustiveScan);
  const deepBtn = document.getElementById("btn-deep-scan");
  if (deepBtn) {
    deepBtn.addEventListener("click", runExhaustiveScan);
  }

  document.querySelectorAll("[data-set-repo]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      document.getElementById("cfg-gh-repo").value = btn.dataset.setRepo;
      await saveIntegrationSettings();
      await openCloudSyncModal("github");
    });
  });

  document.querySelectorAll("[data-sync-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.syncTab;
      document.querySelectorAll("[data-sync-tab]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll(".sync-tab-pane").forEach((p) => {
        p.classList.toggle("hidden", p.id !== targetId);
      });
    });
  });

  ["sync-project", "sync-env"].forEach((id) => {
    document.getElementById(id).addEventListener("change", refreshSyncSnippets);
  });

  document.querySelectorAll("[data-save-cfg]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await saveIntegrationSettings();
        showToast("💾 Configuración guardada y cifrada en bóveda");
      } catch (err) {
        showToast(`❌ ${err.message}`);
      }
    });
  });

  document.querySelectorAll("[data-copy-target]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const area = document.getElementById(btn.dataset.copyTarget);
      if (area) {
        await navigator.clipboard.writeText(area.value);
        showToast("📋 Comando copiado al portapapeles (listo para pegar)");
      }
    });
  });

  document.querySelectorAll("[data-push-target]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const target = btn.dataset.pushTarget;
      const banner = document.getElementById("sync-result-banner");
      banner.classList.remove("hidden");
      banner.innerHTML = `<strong>⏳ Conectando y subiendo secretos a ${escapeHtml(target.toUpperCase())}...</strong>`;

      try {
        await saveIntegrationSettings();
        const res = await apiFetch(`/api/integrations/sync/${target}`, {
          method: "POST",
          body: {
            project: document.getElementById("sync-project").value,
            environment: document.getElementById("sync-env").value,
          },
        });
        const r = res.result || {};
        const pushedList = (r.pushed || []).join(", ") || "Ninguna";
        const errList = (r.errors || []).length
          ? `<br/><span style="color:var(--danger);">Errores: ${escapeHtml(r.errors.join(" | "))}</span>`
          : "";
        banner.innerHTML = `
          <strong>✅ Sincronización completada con ${escapeHtml(target.toUpperCase())}</strong>
          <p>Variables subidas (${(r.pushed || []).length}): <code>${escapeHtml(pushedList)}</code>${errList}</p>
        `;
        showToast(`🚀 ${(r.pushed || []).length} claves enviadas a ${target.toUpperCase()}`);
      } catch (err) {
        banner.innerHTML = `<strong style="color:var(--danger);">❌ Error al sincronizar con ${escapeHtml(target.toUpperCase())}</strong><p>${escapeHtml(err.message)}</p>`;
        showToast(`❌ ${err.message}`);
      }
    });
  });
  ["exp-format", "exp-project", "exp-env"].forEach((id) => {
    document.getElementById(id).addEventListener("change", refreshExportPreview);
  });
  document.getElementById("btn-copy-export").addEventListener("click", async () => {
    const val = document.getElementById("exp-preview").value;
    await navigator.clipboard.writeText(val);
    showToast("📋 Contenido exportado copiado al portapapeles");
  });
  document.getElementById("btn-download-export").addEventListener("click", () => {
    const fmt = document.getElementById("exp-format").value;
    const proj = document.getElementById("exp-project").value;
    const env = document.getElementById("exp-env").value;
    const params = new URLSearchParams({ format: fmt, download: "1" });
    if (proj) params.set("project", proj);
    if (env) params.set("environment", env);
    window.location.href = `/api/export?${params.toString()}`;
  });

  // Importación .env
  document.getElementById("btn-import-env").addEventListener("click", () => {
    document.getElementById("import-form").reset();
    document.getElementById("import-modal").classList.remove("hidden");
  });
  document.getElementById("imp-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (file) {
      document.getElementById("imp-content").value = await file.text();
    }
  });
  document.getElementById("import-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await apiFetch("/api/import-dotenv", {
        method: "POST",
        body: {
          project: document.getElementById("imp-project").value,
          environment: document.getElementById("imp-env").value,
          content: document.getElementById("imp-content").value,
        },
      });
      document.getElementById("import-modal").classList.add("hidden");
      showToast(`📥 ${res.imported} claves importadas y cifradas`);
      await loadKeys();
    } catch (err) {
      showToast(`❌ ${err.message}`);
    }
  });

  // Auditoría
  document.getElementById("btn-audit-logs").addEventListener("click", async () => {
    document.getElementById("audit-modal").classList.remove("hidden");
    const wrap = document.getElementById("audit-list");
    wrap.innerHTML = `<span class="muted-text">Cargando...</span>`;
    try {
      const data = await apiFetch("/api/audit");
      const logs = data.logs || [];
      wrap.innerHTML = `
        <table class="audit-table">
          <thead>
            <tr>
              <th>Fecha (UTC)</th>
              <th>Acción</th>
              <th>Clave</th>
              <th>Detalles</th>
            </tr>
          </thead>
          <tbody>
            ${logs
              .map(
                (l) => `
              <tr>
                <td class="mono-text">${escapeHtml(l.created_at.replace("T", " ").slice(0, 19))}</td>
                <td><strong>${escapeHtml(l.action)}</strong></td>
                <td>${escapeHtml(l.key_name || "—")}</td>
                <td class="muted-text">${escapeHtml(l.details || "")}</td>
              </tr>
            `
              )
              .join("")}
          </tbody>
        </table>
      `;
    } catch (err) {
      wrap.innerHTML = `<span class="muted-text">${escapeHtml(err.message)}</span>`;
    }
  });

  // Cambiar contraseña maestra
  document.getElementById("btn-change-pw").addEventListener("click", () => {
    document.getElementById("pw-form").reset();
    document.getElementById("pw-modal").classList.remove("hidden");
  });
  document.getElementById("pw-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await apiFetch("/api/master-password", {
        method: "POST",
        body: {
          current_password: document.getElementById("pw-current").value,
          new_password: document.getElementById("pw-new").value,
        },
      });
      document.getElementById("pw-modal").classList.add("hidden");
      showToast("🔑 Contraseña maestra actualizada y bóveda recifrada");
    } catch (err) {
      showToast(`❌ ${err.message}`);
    }
  });

  // Cerrar modales
  document.querySelectorAll("[data-close]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.getElementById(btn.dataset.close).classList.add("hidden");
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  checkVaultStatus();
});
