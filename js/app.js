// Arkik Productions - Elite State Management & Reactive UI Engine (v3 - Security Hardened + Calendar + Dual Admin)

// ============================================================
// 0. SECURITY & SANITIZATION LAYER (capa global anti-XSS)
// ============================================================

// Escape HTML: NINGÚN dato de usuario se renderiza por innerHTML sin pasar por aquí
function sanitizeHTML(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Hash FNV-1a de respaldo (entornos sin crypto.subtle)
function fnv1aHex(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return ("00000000" + (h >>> 0).toString(16)).slice(-8);
}

// SHA-256 con WebCrypto (requiere contexto seguro; fallback FNV-1a)
async function sha256Hex(text) {
  try {
    if (crypto && crypto.subtle) {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    }
  } catch (err) { /* fallback */ }
  return fnv1aHex(text);
}

function safeParse(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return fallback;
    const data = JSON.parse(raw);
    return data === undefined || data === null ? fallback : data;
  } catch (err) {
    return fallback;
  }
}

function safeSet(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (err) { /* storage no disponible: no fatal */ }
}

// ============================================================
// 1. PURE HELPERS
// ============================================================

function clampInt(value, min, max) {
  const n = parseInt(value, 10);
  if (Number.isNaN(n)) return min;
  return Math.min(max, Math.max(min, n));
}

function cleanText(value, maxLen) {
  return typeof value === "string" ? value.trim().slice(0, maxLen) : "";
}

// Validación estricta de teléfonos Costa Rica
function isValidCRPhone(phone) {
  return /^(\+?506)?\s?[2678]\d{3}-?\d{4}$/.test(phone.trim());
}

// Referencia SINPE: solo alfanumérico, máx. 15 caracteres
function cleanSinpeRef(value) {
  const cleaned = String(value || "")
    .replace(/[^A-Za-z0-9]/g, "")
    .toUpperCase()
    .slice(0, 15);
  return cleaned || "S/N";
}

function isoOf(date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function parseISO(str) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(str || ""));
  if (!m) return null;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return isNaN(d.getTime()) ? null : d;
}

function startOfMonth(d) {
  return new Date(d.getFullYear(), d.getMonth(), 1);
}

// Normaliza teléfono CR a formato internacional para wa.me
function normalizeWaPhone(phone) {
  let digits = String(phone || "").replace(/\D/g, "");
  if (digits.length === 8) digits = "506" + digits;
  return digits;
}

// Códigos únicos criptográficos: ARK-XXXXXX (crypto.randomUUID)
function generateBookingCode() {
  let hex = "";
  try {
    hex = crypto.randomUUID().replace(/-/g, "");
  } catch (err) {
    hex = Date.now().toString(16) + Math.random().toString(16).slice(2, 12);
  }
  return `ARK-${hex.slice(0, 6).toUpperCase()}`;
}

function formatCRC(n) {
  return `₡${Number(n || 0).toLocaleString("es-CR")}`;
}

function setField(id, value) {
  const el = document.getElementById(id);
  if (el && value) el.value = value;
}

function setPriceText(el, text) {
  if (!el || el.textContent === text) return;
  el.textContent = text;
  el.classList.remove("price-pulse");
  void el.offsetWidth;
  el.classList.add("price-pulse");
}

// ============================================================
// 2. PRICE MANAGER (precios dinámicos modificables por el rol IT)
// ============================================================

const PriceManager = {
  _data: null,

  load() {
    this._data = safeParse(STORAGE_KEYS.prices, { services: {}, extras: {} });
    if (!this._data || typeof this._data !== "object") this._data = { services: {}, extras: {} };
  },

  persist() {
    safeSet(STORAGE_KEYS.prices, this._data);
  },

  getServicePrice(service) {
    if (!service) return 0;
    const p = Number(this._data.services[service.id]);
    return Number.isFinite(p) && p > 0 ? p : service.price_crc;
  },

  getExtraPrice(key) {
    const p = Number(this._data.extras[key]);
    if (Number.isFinite(p) && p > 0) return p;
    const cfg = DYNAMIC_EXTRAS_CONFIG[key];
    return cfg ? cfg.unitPrice : 0;
  },

  setServicePrice(id, price) {
    this._data.services[id] = Math.max(0, Math.round(Number(price) || 0));
    this.persist();
  },

  setExtraPrice(key, price) {
    this._data.extras[key] = Math.max(0, Math.round(Number(price) || 0));
    this.persist();
  },

  reset() {
    this._data = { services: {}, extras: {} };
    this.persist();
  },

  replace(payload) {
    const next = { services: {}, extras: {} };
    const services = (payload && payload.services) || {};
    const extras = (payload && payload.extras) || {};
    Object.keys(services).forEach(k => {
      const v = Number(services[k]);
      if (Number.isFinite(v) && v > 0) next.services[k] = v;
    });
    Object.keys(extras).forEach(k => {
      const v = Number(extras[k]);
      if (Number.isFinite(v) && v > 0) next.extras[k] = v;
    });
    this._data = next;
  },

  exportData() {
    return JSON.parse(JSON.stringify(this._data));
  }
};

// ============================================================
// 3. AVAILABILITY MANAGER (fechas agotadas / deshabilitadas / restablecidas)
// ============================================================

const AvailabilityManager = {
  _data: null,

  load() {
    this._data = safeParse(STORAGE_KEYS.availability, {});
    if (!this._data || typeof this._data !== "object") this._data = {};
  },

  persist() {
    safeSet(STORAGE_KEYS.availability, this._data);
  },

  get(iso) {
    return this._data[iso] || null;
  },

  set(iso, status) {
    if (status === "available") delete this._data[iso];
    else this._data[iso] = status;
    this.persist();
  },

  all() {
    return JSON.parse(JSON.stringify(this._data));
  },

  remainingSlots(iso) {
    return Math.max(0, DEFAULT_SLOTS_PER_DAY - BookingStore.countForDate(iso));
  },

  replace(payload) {
    this._data = {};
    Object.keys(payload || {}).forEach(k => {
      if (payload[k] === "soldout" || payload[k] === "disabled") this._data[k] = payload[k];
    });
  }
};

// ============================================================
// 4. BOOKING STORE (registro persistente de reservas)
// ============================================================

const BookingStore = {
  _data: null,

  load() {
    const raw = safeParse(STORAGE_KEYS.bookings, []);
    this._data = Array.isArray(raw) ? raw : [];
  },

  persist() {
    safeSet(STORAGE_KEYS.bookings, this._data);
  },

  all() {
    return this._data;
  },

  add(booking) {
    this._data.unshift(booking);
    this.persist();
  },

  get(code) {
    return this._data.find(b => b.code === code) || null;
  },

  updateStatus(code, status) {
    const b = this.get(code);
    if (b && BOOKING_STATUSES[status]) {
      b.status = status;
      this.persist();
    }
  },

  countForDate(iso) {
    return this._data.filter(b => b.selectedDate === iso && b.status !== "cancelada").length;
  },

  replace(list) {
    this._data = Array.isArray(list) ? list : [];
  }
};

// ============================================================
// 5. SECURITY MODULE (PIN hasheado + anti fuerza bruta)
// ============================================================

const SecurityModule = {
  _data: null,

  load() {
    this._data = safeParse(STORAGE_KEYS.admin, { ownerHash: null, itHash: null, attempts: 0, lockoutUntil: 0 });
  },

  persist() {
    safeSet(STORAGE_KEYS.admin, this._data);
  },

  async verifyPin(roleId, pin) {
    this.load();
    const now = Date.now();
    if (this._data.lockoutUntil && now < this._data.lockoutUntil) {
      return { ok: false, locked: true, waitMs: this._data.lockoutUntil - now };
    }

    const role = ADMIN_CONFIG.roles[roleId];
    if (!role) return { ok: false, locked: false, remaining: ADMIN_CONFIG.maxAttempts };

    const inputHash = await sha256Hex(String(pin).trim());
    const expected = this._data[role.hashKey] || (await sha256Hex(role.defaultPin));

    if (inputHash === expected) {
      this._data.attempts = 0;
      this._data.lockoutUntil = 0;
      this.persist();
      return { ok: true };
    }

    this._data.attempts = (this._data.attempts || 0) + 1;
    if (this._data.attempts >= ADMIN_CONFIG.maxAttempts) {
      this._data.lockoutUntil = now + ADMIN_CONFIG.lockoutMs;
      this._data.attempts = 0;
    }
    this.persist();
    return { ok: false, locked: false, remaining: Math.max(0, ADMIN_CONFIG.maxAttempts - this._data.attempts) };
  }
};

// ============================================================
// 6. CART STATE (motor de precios intacto + fecha/hora de calendario)
// ============================================================

class CartState {
  constructor() {
    this.selectedService = CATALOG_SERVICES[0] || null;
    this.extraHoursCount = 0;
    this.djHoursCount = 0;
    this.subwoofersCount = 0;
    this.province = "";
    this.canton = "";
    this.clientName = "";
    this.clientPhone = "";
    this.clientEmail = "";
    this.eventType = "Boda";
    this.selectedDate = "";
    this.selectedTime = "";
    this.address = "";
    this.sinpeRef = "";
    this.createdBooking = null;
    this.currentStep = 1;
    this.isSubmitting = false;
    this.restore();
  }

  // ---- Pricing Engine (matemática previa intacta, colones enteros) ----

  get extraHoursUnitPrice() {
    if (!this.selectedService) return 0;
    return Math.round(PriceManager.getServicePrice(this.selectedService) * 0.50);
  }

  get extraHoursTotal() {
    return this.extraHoursUnitPrice * this.extraHoursCount;
  }

  get djTotal() {
    return PriceManager.getExtraPrice("dj_service") * this.djHoursCount;
  }

  get subwoofersTotal() {
    return PriceManager.getExtraPrice("subwoofers") * this.subwoofersCount;
  }

  get subtotal() {
    const base = this.selectedService ? PriceManager.getServicePrice(this.selectedService) : 0;
    return base + this.extraHoursTotal + this.djTotal + this.subwoofersTotal;
  }

  get isNonGam() {
    if (!this.province) return false;
    if (!GAM_PROVINCES.includes(this.province)) return true;
    if (!this.canton) return false;
    return (NON_GAM_EXCEPTIONS[this.province] || []).includes(this.canton);
  }

  get locationKnown() {
    return Boolean(this.province && this.canton);
  }

  get travelSurcharge() {
    return this.isNonGam ? Math.round(this.subtotal * NON_GAM_SURCHARGE_RATE) : 0;
  }

  get granTotal() {
    return this.subtotal + this.travelSurcharge;
  }

  get deposit50Amount() {
    return Math.round(this.granTotal * SINPE_CONFIG.depositPercentage);
  }

  get remainingBalance() {
    return this.granTotal - this.deposit50Amount;
  }

  // ---- Persistence (recuperación tras refresh) ----

  serialize() {
    return {
      serviceId: this.selectedService ? this.selectedService.id : null,
      extraHoursCount: this.extraHoursCount,
      djHoursCount: this.djHoursCount,
      subwoofersCount: this.subwoofersCount,
      province: this.province,
      canton: this.canton,
      clientName: this.clientName,
      clientPhone: this.clientPhone,
      clientEmail: this.clientEmail,
      eventType: this.eventType,
      selectedDate: this.selectedDate,
      selectedTime: this.selectedTime,
      address: this.address,
      sinpeRef: this.sinpeRef
    };
  }

  persist() {
    safeSet(STORAGE_KEYS.cart, this.serialize());
  }

  restore() {
    try {
      const data = safeParse(STORAGE_KEYS.cart, null);
      if (!data || typeof data !== "object") return;

      if (data.serviceId) {
        const svc = CATALOG_SERVICES.find(s => s.id === data.serviceId);
        if (svc) this.selectedService = svc;
      }
      this.extraHoursCount = clampInt(data.extraHoursCount, 0, MAX_EXTRAS.extraHoursCount);
      this.djHoursCount = clampInt(data.djHoursCount, 0, MAX_EXTRAS.djHoursCount);
      this.subwoofersCount = clampInt(data.subwoofersCount, 0, MAX_EXTRAS.subwoofersCount);

      if (data.province && PROVINCES_AND_CANTONES[data.province]) {
        this.province = data.province;
        if (PROVINCES_AND_CANTONES[data.province].includes(data.canton)) {
          this.canton = data.canton;
        }
      }
      this.clientName = cleanText(data.clientName, 120);
      this.clientPhone = cleanText(data.clientPhone, 30);
      this.clientEmail = cleanText(data.clientEmail, 120);
      this.eventType = cleanText(data.eventType, 40) || "Boda";
      this.address = cleanText(data.address, 300);
      this.sinpeRef = cleanText(data.sinpeRef, 15);

      const savedDate = cleanText(data.selectedDate || data.eventDate, 10);
      if (parseISO(savedDate)) this.selectedDate = savedDate;
      const savedTime = cleanText(data.selectedTime || data.eventTime, 5);
      if (/^([01]\d|2[0-3]):[0-5]\d$/.test(savedTime)) this.selectedTime = savedTime;
    } catch (err) {
      // Payload corrupto: continuar con valores por defecto
    }
  }

  clearStoredState() {
    try {
      localStorage.removeItem(STORAGE_KEYS.cart);
    } catch (err) {
      // ignore
    }
  }
}

// ============================================================
// 7. CALENDAR MODULE (disponibilidad + franjas horarias)
// ============================================================

const CalendarModule = {
  viewDate: null,
  selectedDate: "",
  selectedTime: "",

  init() {
    if (!cart.selectedDate) this.viewDate = startOfMonth(new Date());
    else {
      const d = parseISO(cart.selectedDate);
      this.viewDate = startOfMonth(d || new Date());
      this.selectedDate = cart.selectedDate;
    }
    this.selectedTime = cart.selectedTime || "";
    this.render();
  },

  reset() {
    this.viewDate = null;
    this.selectedDate = "";
    this.selectedTime = "";
  },

  render() {
    const grid = document.getElementById("calendar-grid");
    const label = document.getElementById("cal-month-label");
    if (!grid) return;

    const todayISO = isoOf(new Date());
    this.viewDate = this.viewDate || startOfMonth(new Date());
    const y = this.viewDate.getFullYear();
    const m = this.viewDate.getMonth();
    if (label) label.textContent = `${CALENDAR_LOCALE.months[m]} ${y}`;

    const daysInMonth = new Date(y, m + 1, 0).getDate();
    const offset = (new Date(y, m, 1).getDay() + 6) % 7;

    let cells = "";
    for (let i = 0; i < offset; i++) cells += `<div class="ark-cal-day--empty"></div>`;

    for (let d = 1; d <= daysInMonth; d++) {
      const iso = `${y}-${String(m + 1).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      const state = this.getDayState(iso, todayISO);
      const isToday = iso === todayISO;
      const isSelected = iso === this.selectedDate;
      const css = [
        "ark-cal-day",
        state.css,
        isToday ? "ark-cal-day--today" : "",
        isSelected ? "ark-cal-day--selected" : ""
      ].join(" ").trim();
      cells += `
        <button type="button" class="${css}" data-date="${iso}" ${state.selectable ? "" : "disabled"}
          aria-label="${iso} — ${state.label || "No disponible"}">
          <span class="ark-cal-day-num">${d}</span>
          <span class="ark-cal-day-label">${state.label}</span>
        </button>`;
    }

    grid.innerHTML = cells;
    this.renderTimeSlots();
    this.renderSummary();
  },

  getDayState(iso, todayISO) {
    if (iso < todayISO) return { css: "ark-cal-day--past", label: "", selectable: false };
    const override = AvailabilityManager.get(iso);
    if (override === "soldout") return { css: "ark-cal-day--soldout", label: "Agotado", selectable: false };
    if (override === "disabled") return { css: "ark-cal-day--disabled", label: "Bloqueado", selectable: false };
    const remaining = AvailabilityManager.remainingSlots(iso);
    if (override === "available" || remaining > LOW_SLOTS_THRESHOLD) {
      return { css: "ark-cal-day--available", label: `${remaining} lugares`, selectable: true };
    }
    if (remaining > 0) return { css: "ark-cal-day--few", label: `${remaining} lugares`, selectable: true };
    return { css: "ark-cal-day--soldout", label: "Agotado", selectable: false };
  },

  shiftMonth(delta) {
    this.viewDate = new Date(this.viewDate.getFullYear(), this.viewDate.getMonth() + delta, 1);
    this.render();
  },

  selectDate(iso) {
    this.selectedDate = iso;
    this.selectedTime = "";
    cart.selectedDate = iso;
    cart.selectedTime = "";
    cart.persist();
    this.render();
    showToast("Fecha seleccionada. Elija la hora de inicio.", "success");
  },

  selectTime(time) {
    this.selectedTime = time;
    cart.selectedTime = time;
    cart.persist();
    this.renderTimeSlots();
    this.renderSummary();
  },

  renderTimeSlots() {
    const box = document.getElementById("time-slots");
    if (!box) return;

    if (!this.selectedDate) {
      box.innerHTML = `
        <p class="text-xs text-gray-500 text-center py-3">
          🗓️ Seleccione una fecha disponible para elegir la hora de inicio del show.
        </p>`;
      return;
    }

    const isToday = this.selectedDate === isoOf(new Date());
    const nowMins = isToday ? (new Date().getHours() * 60 + new Date().getMinutes()) : -1;

    box.innerHTML = Object.values(TIME_SLOTS).map(group => `
      <div class="ark-time-group">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold text-purple-300 uppercase tracking-wider">${group.label}</span>
          <span class="text-[10px] text-gray-500">${group.range}</span>
        </div>
        <div class="flex flex-wrap gap-2">
          ${group.times.map(t => {
            const [hh, mm] = t.split(":").map(Number);
            const expired = isToday && (hh * 60 + mm) <= nowMins;
            const sel = t === this.selectedTime;
            const disabledCls = expired ? "ark-time-chip--past" : "";
            const selectedCls = sel ? "ark-time-chip--selected" : "";
            return `<button type="button" data-time="${t}" ${expired ? "disabled" : ""}
              class="ark-time-chip ${disabledCls} ${selectedCls}">${t}</button>`;
          }).join("")}
        </div>
      </div>`).join("");
  },

  renderSummary() {
    const el = document.getElementById("date-summary");
    if (!el) return;
    if (!this.selectedDate) {
      el.textContent = "Ninguna fecha seleccionada";
      return;
    }
    const [y, m, d] = this.selectedDate.split("-").map(Number);
    const name = CALENDAR_LOCALE.months[m - 1];
    const week = CALENDAR_LOCALE.weekdays[(new Date(y, m - 1, d).getDay() + 6) % 7];
    const t = this.selectedTime ? ` · ${this.selectedTime}` : " (seleccione hora)";
    el.textContent = `${week} ${d} de ${name} ${y}${t}`;
  }
};

// ============================================================
// 8. ADMIN MODULE (dashboard dual: Propietario / Ingeniero de TI)
// ============================================================

const AdminModule = {
  role: "",
  ownerFilter: "todas",

  open() {
    const modal = document.getElementById("adminModal");
    if (!modal) return;
    modal.classList.remove("hidden");
    modal.classList.add("flex");
    document.body.style.overflow = "hidden";
    this.showAuth();
  },

  close() {
    const modal = document.getElementById("adminModal");
    if (!modal) return;
    modal.classList.add("hidden");
    modal.classList.remove("flex");
    document.body.style.overflow = "";
  },

  showAuth() {
    this.role = "";
    const authView = document.getElementById("admin-auth-view");
    const dashView = document.getElementById("admin-dashboard-view");
    if (authView) authView.classList.remove("hidden");
    if (dashView) dashView.classList.add("hidden");
    const pin = document.getElementById("admin-pin");
    if (pin) pin.value = "";
    this.clearAuthError();
    this.setRole("owner");
  },

  setRole(roleId) {
    this.role = roleId;
    const ownerBtn = document.getElementById("admin-role-owner");
    const itBtn = document.getElementById("admin-role-it");
    if (ownerBtn) ownerBtn.classList.toggle("admin-role-btn--active", roleId === "owner");
    if (itBtn) itBtn.classList.toggle("admin-role-btn--active", roleId === "it");
    const pin = document.getElementById("admin-pin");
    if (pin) pin.focus();
  },

  clearAuthError() {
    const el = document.getElementById("admin-auth-error");
    if (el) {
      el.classList.add("hidden");
      el.textContent = "";
    }
  },

  showAuthError(msg) {
    const el = document.getElementById("admin-auth-error");
    if (el) {
      el.textContent = msg;
      el.classList.remove("hidden");
    }
  },

  async attemptLogin() {
    const pin = document.getElementById("admin-pin");
    const value = pin ? pin.value.trim() : "";
    if (!this.role) { this.showAuthError("Seleccione un rol."); return; }
    if (!value) { this.showAuthError("Ingrese su PIN de acceso."); return; }

    const result = await SecurityModule.verifyPin(this.role, value);
    if (result.ok) {
      this.renderDashboard();
    } else if (result.locked) {
      this.showAuthError(`Bloqueado temporalmente. Espere ${Math.ceil(result.waitMs / 1000)} segundos.`);
    } else {
      this.showAuthError(result.remaining > 0
        ? `PIN incorrecto. Intentos restantes: ${result.remaining}.`
        : "PIN incorrecto.");
    }
  },

  logout() {
    this.showAuth();
  },

  renderDashboard() {
    const authView = document.getElementById("admin-auth-view");
    const dashView = document.getElementById("admin-dashboard-view");
    if (authView) authView.classList.add("hidden");
    if (dashView) dashView.classList.remove("hidden");

    const role = ADMIN_CONFIG.roles[this.role];
    const badge = document.getElementById("admin-role-badge");
    if (badge) {
      badge.textContent = `${role.label} · ${role.name}`;
      badge.className = `admin-role-badge ${this.role === "owner" ? "admin-role-badge--owner" : "admin-role-badge--it"}`;
    }

    const ownerView = document.getElementById("admin-owner-view");
    const itView = document.getElementById("admin-it-view");
    if (ownerView) ownerView.classList.toggle("hidden", this.role !== "owner");
    if (itView) itView.classList.toggle("hidden", this.role !== "it");

    if (this.role === "owner") this.renderOwner();
    else this.renderIT();
  },

  // ---- Rol Propietario ----

  renderOwner() {
    this.renderOwnerMetrics();
    this.renderOwnerFilters();
    this.renderOwnerBookings();
  },

  renderOwnerMetrics() {
    const active = BookingStore.all().filter(b => b.status !== "cancelada");
    const total = active.reduce((s, b) => s + b.granTotal, 0);
    const deposits = active.reduce((s, b) => s + b.deposit50Amount, 0);
    const pending = active.reduce((s, b) => s + b.remainingBalance, 0);
    const box = document.getElementById("admin-metrics");
    if (!box) return;
    box.innerHTML = [
      metricCard("Reservas Activas", String(active.length), "border-purple-500/40"),
      metricCard("Total Acumulado", formatCRC(total), "border-emerald-500/40"),
      metricCard("Adelantos SINPE (50%)", formatCRC(deposits), "border-cyan-500/40"),
      metricCard("Saldo por Cobrar", formatCRC(pending), "border-pink-500/40")
    ].join("");
  },

  renderOwnerFilters() {
    const box = document.getElementById("admin-status-filters");
    if (!box) return;
    const statuses = [["todas", "Todas"], ["pendiente", "Pendientes"], ["confirmada", "Confirmadas"], ["cancelada", "Canceladas"]];
    box.innerHTML = statuses.map(([key, label]) => {
      const count = key === "todas"
        ? BookingStore.all().length
        : BookingStore.all().filter(b => b.status === key).length;
      const active = key === this.ownerFilter ? "admin-tab-btn--active" : "";
      return `<button type="button" data-filter="${key}" class="admin-tab-btn ${active}">${label} (${count})</button>`;
    }).join("");
  },

  renderOwnerBookings() {
    const box = document.getElementById("admin-bookings-list");
    if (!box) return;
    const list = BookingStore.all().filter(b => this.ownerFilter === "todas" || b.status === this.ownerFilter);
    if (!list.length) {
      box.innerHTML = `<p class="text-xs text-gray-500 text-center py-6">No hay reservas registradas en esta categoría.</p>`;
      return;
    }
    box.innerHTML = list.map(bookingRow).join("");
  },

  // ---- Rol Ingeniero de TI ----

  renderIT() {
    const tabs = ["availability", "prices", "backup"];
    tabs.forEach(p => {
      const el = document.getElementById(`admin-it-${p}`);
      if (el) el.classList.toggle("hidden", p !== "availability");
    });
    document.querySelectorAll("[data-it-tab]").forEach(t => {
      t.classList.toggle("admin-tab-btn--active", t.getAttribute("data-it-tab") === "availability");
    });

    const availEl = document.getElementById("admin-it-availability");
    const pricesEl = document.getElementById("admin-it-prices");
    const backupEl = document.getElementById("admin-it-backup");
    if (availEl) availEl.innerHTML = this.itAvailabilityHtml();
    if (pricesEl) pricesEl.innerHTML = this.itPricesHtml();
    if (backupEl) backupEl.innerHTML = this.itBackupHtml();
  },

  itAvailabilityHtml() {
    const todayISO = isoOf(new Date());
    const overrides = AvailabilityManager.all();
    const entries = Object.keys(overrides).sort();
    return `
      <div>
        <p class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">Marcar Fecha</p>
        <div class="flex flex-wrap items-end gap-2">
          <input type="date" id="admin-avail-date" min="${todayISO}"
            class="glass-input rounded-xl px-3 py-2.5 text-sm">
          <button type="button" data-avail="soldout" class="admin-act-btn admin-act-btn--cancel">🔴 Marcar Agotado</button>
          <button type="button" data-avail="disabled" class="admin-act-btn admin-act-btn--neutral">⛔ Deshabilitar</button>
          <button type="button" data-avail="available" class="admin-act-btn admin-act-btn--confirm">🟢 Restablecer</button>
        </div>
      </div>
      <div>
        <p class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">Fechas con Gestión Manual (${entries.length})</p>
        <div class="space-y-2">
          ${entries.length ? entries.map(k => `
            <div class="flex items-center justify-between gap-3 p-3 rounded-xl bg-white/5 border border-white/10">
              <span class="text-sm font-bold text-white">${k}</span>
              <span class="status-badge ${overrides[k] === "soldout" ? "status-badge--soldout" : "status-badge--disabled"}">
                ${overrides[k] === "soldout" ? "Agotado" : "Deshabilitado"}
              </span>
              <button type="button" data-avail-remove="${k}" class="text-xs text-red-400 hover:text-red-300">Quitar</button>
            </div>`).join("")
            : `<p class="text-xs text-gray-500">Sin gestiones manuales. La disponibilidad se calcula automáticamente (${DEFAULT_SLOTS_PER_DAY} lugares por día).</p>`}
        </div>
      </div>`;
  },

  itPricesHtml() {
    const services = CATALOG_SERVICES.map(s => `
      <div class="flex items-center justify-between gap-3 p-3 rounded-xl bg-white/5 border border-white/10">
        <div class="min-w-0">
          <p class="text-sm font-bold text-white truncate">${sanitizeHTML(s.name)}</p>
          <p class="text-[10px] text-gray-500">Original: ${formatCRC(s.price_crc)}</p>
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <span class="text-xs text-gray-400">₡</span>
          <input type="number" data-price="service-${s.id}" value="${PriceManager.getServicePrice(s)}"
            min="0" step="1000" class="glass-input rounded-xl px-3 py-2 w-36 text-sm">
        </div>
      </div>`).join("");

    const extras = [
      ["dj_service", "Servicio de DJ para Recesos (por hora)"],
      ["subwoofers", 'Subwoofers Extra de 18" (por unidad)']
    ].map(([key, name]) => `
      <div class="flex items-center justify-between gap-3 p-3 rounded-xl bg-white/5 border border-white/10">
        <div class="min-w-0">
          <p class="text-sm font-bold text-white">${name}</p>
          <p class="text-[10px] text-gray-500">Original: ${formatCRC(DYNAMIC_EXTRAS_CONFIG[key].unitPrice)}</p>
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <span class="text-xs text-gray-400">₡</span>
          <input type="number" data-price="extra-${key}" value="${PriceManager.getExtraPrice(key)}"
            min="0" step="1000" class="glass-input rounded-xl px-3 py-2 w-36 text-sm">
        </div>
      </div>`).join("");

    return `
      <div>
        <p class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">Precios Base de Formatos (en tiempo real)</p>
        <div class="space-y-2">${services}</div>
      </div>
      <div>
        <p class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">Precios de Extras</p>
        <div class="space-y-2">${extras}</div>
      </div>
      <div class="flex flex-wrap gap-3 pt-2">
        <button type="button" id="admin-save-prices" class="admin-act-btn admin-act-btn--confirm">💾 Guardar Precios</button>
        <button type="button" id="admin-reset-prices" class="admin-act-btn admin-act-btn--neutral">↺ Restaurar Originales</button>
      </div>`;
  },

  itBackupHtml() {
    return `
      <div class="p-5 rounded-2xl bg-white/5 border border-purple-500/30 space-y-4">
        <p class="text-sm font-bold text-white">Respaldo de Datos</p>
        <p class="text-xs text-gray-400 leading-relaxed">Exporte la base de datos completa (reservas, disponibilidad y
          precios) como archivo JSON, o importe un respaldo previo para restaurar el sistema.</p>
        <div class="flex flex-wrap gap-3">
          <button type="button" id="admin-export-backup" class="admin-act-btn admin-act-btn--confirm">⬇ Exportar Base de Datos (JSON)</button>
          <label class="admin-act-btn admin-act-btn--neutral cursor-pointer">
            ⬆ Importar Respaldo
            <input type="file" id="admin-import-backup" accept=".json,application/json" class="hidden">
          </label>
        </div>
        <p id="admin-backup-status" class="text-[10px] text-gray-500">
          Estado actual: ${BookingStore.all().length} reservas · ${Object.keys(AvailabilityManager.all()).length} fechas gestionadas
        </p>
      </div>`;
  }
};

function metricCard(label, value, border) {
  return `
    <div class="p-4 rounded-2xl bg-white/5 border ${border} backdrop-blur-md">
      <p class="text-[10px] font-bold uppercase tracking-wider text-gray-400">${label}</p>
      <p class="text-lg font-extrabold text-white mt-1 break-all">${value}</p>
    </div>`;
}

function bookingRow(b) {
  const statusLabel = BOOKING_STATUSES[b.status] || b.status;
  const name = sanitizeHTML(b.clientName);
  return `
  <div class="admin-booking-row rounded-2xl border border-purple-500/20 bg-white/5 p-4" data-id="${b.code}">
    <div class="flex flex-wrap items-center justify-between gap-2 mb-3">
      <div class="flex items-center gap-2">
        <span class="font-extrabold text-purple-300 text-sm">${b.code}</span>
        <span class="status-badge status-badge--${b.status}">${statusLabel}</span>
      </div>
      <span class="text-xs text-gray-400">📅 ${b.selectedDate} · ${b.selectedTime}</span>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-xs text-gray-300">
      <p><span class="text-gray-500">Cliente:</span> ${name}</p>
      <p><span class="text-gray-500">Formato:</span> ${sanitizeHTML(b.serviceName)}</p>
      <p><span class="text-gray-500">Ubicación:</span> ${sanitizeHTML(b.canton)}, ${sanitizeHTML(b.province)}</p>
      <p><span class="text-gray-500">Ref. SINPE:</span> ${b.sinpeRef ? sanitizeHTML(b.sinpeRef) : "S/N"}</p>
      <p><span class="text-gray-500">Gran Total:</span> <span class="font-bold text-white">${formatCRC(b.granTotal)}</span></p>
      <p><span class="text-gray-500">Adelanto (50%):</span> <span class="font-bold text-emerald-400">${formatCRC(b.deposit50Amount)}</span></p>
    </div>
    <div class="flex flex-wrap gap-2 mt-4">
      <button type="button" data-action="confirm" ${b.status === "confirmada" ? "disabled" : ""}
        class="admin-act-btn admin-act-btn--confirm">✓ Confirmar</button>
      <button type="button" data-action="pending" ${b.status === "pendiente" ? "disabled" : ""}
        class="admin-act-btn admin-act-btn--neutral">↩ Pendiente</button>
      <button type="button" data-action="cancel" ${b.status === "cancelada" ? "disabled" : ""}
        class="admin-act-btn admin-act-btn--cancel">✕ Cancelar</button>
      <button type="button" data-action="receipt" class="admin-act-btn admin-act-btn--neutral">🧾 Verificar Comprobante</button>
      <button type="button" data-action="whatsapp" class="admin-act-btn admin-act-btn--whatsapp">💬 WhatsApp</button>
    </div>
  </div>`;
}

function whatsappClientUrl(booking, message) {
  return `https://wa.me/${normalizeWaPhone(booking.clientPhone)}?text=${encodeURIComponent(message)}`;
}

// ============================================================
// 9. GLOBAL APP INSTANCE & BOOT
// ============================================================

const cart = new CartState();

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

function initApp() {
  PriceManager.load();
  BookingStore.load();
  AvailabilityManager.load();
  renderCatalog(CATALOG_SERVICES);
  renderGalleryFilters();
  renderMediaGallery(mediaLibrary, 'todos');
  setupEventListeners();
  populateProvinces();
  restoreBookingToUI();
  initFooterFluidEffect();
  initHeroStringsEffect();
}

// ============================================================
// 10. CATALOG & GALLERY RENDERING (todo contenido sanitizado)
// ============================================================

let currentCatalogCategory = 'Todos';

function renderCatalog(services, category = 'Todos') {
  const container = document.getElementById('catalog-grid');
  if (!container) return;
  currentCatalogCategory = category;

  const filtered = category === 'Todos'
    ? services
    : services.filter(s => s.category === category);

  container.innerHTML = filtered.map(service => `
    <div class="glass-panel rounded-2xl overflow-hidden flex flex-col justify-between group transform hover:-translate-y-2 transition-all duration-300 relative">
      ${service.badge ? `
        <span class="absolute top-4 right-4 z-10 bg-gradient-to-r from-purple-600 to-pink-600 text-white text-xs font-bold px-3 py-1 rounded-full shadow-lg">
          ${sanitizeHTML(service.badge)}
        </span>
      ` : ''}

      <div>
        <div class="relative h-56 overflow-hidden">
          <img src="${service.image_url}" alt="${sanitizeHTML(service.name)}" class="w-full h-full object-cover group-hover:scale-110 transition-transform duration-300" />
          <div class="absolute inset-0 bg-gradient-to-t from-[#0b0914] via-transparent to-transparent"></div>
          <span class="absolute bottom-3 left-4 text-xs font-semibold px-2.5 py-1 rounded-md bg-purple-950/80 border border-purple-500/40 text-purple-300">
            ${sanitizeHTML(service.category)}
          </span>
        </div>

        <div class="p-6">
          <h3 class="text-xl font-bold text-white group-hover:text-purple-300 transition-colors">${sanitizeHTML(service.name)}</h3>
          <p class="text-sm text-gray-400 mt-2 line-clamp-3 leading-relaxed">${sanitizeHTML(service.description)}</p>

          <div class="mt-4 pt-4 border-t border-purple-500/20 space-y-2">
            <div class="flex items-center text-xs text-purple-300 font-medium">
              <svg class="w-4 h-4 mr-2 text-pink-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
              ${sanitizeHTML(service.duration)}
            </div>
            <div class="flex items-start text-xs text-gray-400">
              <svg class="w-4 h-4 mr-2 text-purple-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
              <span>${sanitizeHTML(service.tech_specs)}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="p-6 pt-0">
        <div class="flex items-baseline justify-between mb-4">
          <span class="text-xs text-gray-400 font-medium">Tarifa Base (2 hrs)</span>
          <span class="text-2xl font-extrabold text-gradient-purple">₡${PriceManager.getServicePrice(service).toLocaleString('es-CR')}</span>
        </div>

        <button onclick="openBookingModal(${service.id})" class="w-full py-3 px-4 rounded-xl font-bold text-white bg-gradient-to-r from-purple-600 via-indigo-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 shadow-lg shadow-purple-900/30 hover:shadow-purple-600/40 transition-all flex items-center justify-center space-x-2">
          <span>Cotizar y Reservar</span>
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"></path></svg>
        </button>
      </div>
    </div>
  `).join('');
}

// ---- Elite Media Library (Biblioteca Multimedia) ----

function renderGalleryFilters(activeKey = 'todos') {
  const container = document.getElementById('gallery-filters');
  if (!container) return;

  const counts = {};
  mediaLibrary.forEach(m => {
    counts[m.category] = (counts[m.category] || 0) + 1;
  });

  container.innerHTML = GALLERY_FILTERS.map(filter => {
    const count = filter.key === 'todos' ? mediaLibrary.length : (counts[filter.key] || 0);
    const active = filter.key === activeKey;
    const base = 'gallery-filter-btn min-h-[44px] px-4 py-2.5 rounded-xl text-xs font-bold transition-all duration-300 border';
    const state = active
      ? ' bg-gradient-to-r from-purple-600 to-pink-600 text-white border-transparent shadow-lg shadow-purple-900/40'
      : ' bg-white/5 text-gray-300 border-white/10 hover:text-white hover:border-purple-500/40 hover:bg-purple-500/10';
    return `<button type="button" data-filter="${filter.key}" class="${base}${state}">${sanitizeHTML(filter.label)} <span class="opacity-60 font-semibold">(${count})</span></button>`;
  }).join('');
}

function renderMediaGallery(items, filterKey = 'todos') {
  const container = document.getElementById('gallery-grid');
  if (!container) return;

  const filtered = filterKey === 'todos' ? items : items.filter(item => item.category === filterKey);

  container.innerHTML = filtered.map(item =>
    item.type === 'video' ? galleryVideoCard(item) : galleryImageCard(item)
  ).join('');
}

function galleryCategoryBadge(item) {
  const label = GALLERY_CATEGORY_LABELS[item.category] || item.category;
  return `
    <span class="absolute top-3 left-3 z-10 px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider bg-[#0a0712]/80 border border-purple-500/30 text-purple-300 backdrop-blur-sm">
      ${sanitizeHTML(label)}
    </span>
  `;
}

function galleryCardShell(item, mediaHtml) {
  return `
    <article class="gallery-card group relative rounded-2xl overflow-hidden border border-white/10 bg-white/5 backdrop-blur-xl transition-all duration-300 hover:scale-[1.02] hover:border-purple-500/50 hover:shadow-[0_8px_40px_rgba(168,85,247,0.25)]">
      ${mediaHtml}
      <div class="p-5">
        <h4 class="text-sm font-bold text-white group-hover:text-purple-300 transition-colors leading-snug">${sanitizeHTML(item.title)}</h4>
        ${item.subtitle ? `<p class="text-xs text-gray-400 mt-1">${sanitizeHTML(item.subtitle)}</p>` : ''}
      </div>
    </article>
  `;
}

function galleryVideoCard(item) {
  const media = `
    <div id="gallery-media-${item.id}" class="relative aspect-video overflow-hidden">
      <img src="${item.thumbnail}" alt="${sanitizeHTML(item.title)}" loading="lazy"
        class="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110" />
      <div class="absolute inset-0 bg-gradient-to-t from-[#0a0712] via-[#0a0712]/25 to-transparent"></div>
      ${galleryCategoryBadge(item)}
      <button type="button" onclick="playGalleryVideo(${item.id})" aria-label="Reproducir video: ${sanitizeHTML(item.title)}"
        class="absolute inset-0 m-auto z-10 w-16 h-16 rounded-full bg-gradient-to-tr from-purple-600 to-pink-500 flex items-center justify-center shadow-2xl shadow-purple-900/60 border border-white/20 backdrop-blur-sm transition-transform duration-300 hover:scale-110 active:scale-95">
        <span class="absolute inset-0 rounded-full bg-purple-500/40 animate-ping opacity-0 group-hover:opacity-100 [animation-duration:1.6s]"></span>
        <svg class="w-7 h-7 text-white ml-1" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"></path></svg>
      </button>
    </div>
  `;
  return galleryCardShell(item, media);
}

function galleryImageCard(item) {
  const media = `
    <div class="relative aspect-[4/3] overflow-hidden">
      <img src="${item.url}" alt="${sanitizeHTML(item.title)}" loading="lazy"
        class="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110" />
      <div class="absolute inset-0 bg-gradient-to-t from-[#0a0712]/80 via-transparent to-transparent"></div>
      ${galleryCategoryBadge(item)}
    </div>
  `;
  return galleryCardShell(item, media);
}

function playGalleryVideo(id) {
  const item = mediaLibrary.find(m => m.id === id);
  const mediaBox = document.getElementById(`gallery-media-${id}`);
  if (!item || item.type !== 'video' || !mediaBox) return;

  mediaBox.innerHTML = '';
  const iframe = document.createElement('iframe');
  iframe.src = item.url + (item.url.includes('?') ? '&' : '?') + 'autoplay=1';
  iframe.title = item.title;
  iframe.setAttribute('allow', 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share');
  iframe.setAttribute('allowfullscreen', '');
  iframe.className = 'absolute inset-0 w-full h-full border-0';
  mediaBox.appendChild(iframe);
}

// ============================================================
// 11. EVENT LISTENERS
// ============================================================

function setupEventListeners() {
  const filterBtns = document.querySelectorAll('.filter-btn');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      filterBtns.forEach(b => {
        b.classList.remove('bg-purple-600', 'text-white', 'shadow-lg');
        b.classList.add('glass-panel', 'text-gray-300');
      });
      e.target.classList.remove('glass-panel', 'text-gray-300');
      e.target.classList.add('bg-purple-600', 'text-white', 'shadow-lg');

      const category = e.target.getAttribute('data-category');
      renderCatalog(CATALOG_SERVICES, category);
    });
  });

  const galleryFilters = document.getElementById('gallery-filters');
  if (galleryFilters) {
    galleryFilters.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-filter]');
      if (!btn) return;
      const filterKey = btn.getAttribute('data-filter');
      renderGalleryFilters(filterKey);
      renderMediaGallery(mediaLibrary, filterKey);
    });
  }

  const provSelect = document.getElementById('booking-province');
  if (provSelect) {
    provSelect.addEventListener('change', (e) => {
      cart.province = e.target.value;
      cart.canton = "";
      populateCantones(e.target.value);
      updateSummaryPrices();
      cart.persist();
    });
  }

  const cantonSelect = document.getElementById('booking-canton');
  if (cantonSelect) {
    cantonSelect.addEventListener('change', (e) => {
      cart.canton = e.target.value;
      updateSummaryPrices();
      cart.persist();
    });
  }

  // --- Calendario: navegación de mes, días y franjas horarias ---
  const calPrev = document.getElementById('cal-prev');
  if (calPrev) calPrev.addEventListener('click', () => CalendarModule.shiftMonth(-1));
  const calNext = document.getElementById('cal-next');
  if (calNext) calNext.addEventListener('click', () => CalendarModule.shiftMonth(1));

  const calGrid = document.getElementById('calendar-grid');
  if (calGrid) {
    calGrid.addEventListener('click', (e) => {
      const day = e.target.closest('[data-date]');
      if (!day || day.disabled) return;
      CalendarModule.selectDate(day.getAttribute('data-date'));
    });
  }

  const timeBox = document.getElementById('time-slots');
  if (timeBox) {
    timeBox.addEventListener('click', (e) => {
      const chip = e.target.closest('[data-time]');
      if (!chip || chip.disabled) return;
      CalendarModule.selectTime(chip.getAttribute('data-time'));
    });
  }

  // --- Admin: autenticación ---
  const roleOwner = document.getElementById('admin-role-owner');
  if (roleOwner) roleOwner.addEventListener('click', () => AdminModule.setRole('owner'));
  const roleIt = document.getElementById('admin-role-it');
  if (roleIt) roleIt.addEventListener('click', () => AdminModule.setRole('it'));
  const adminPin = document.getElementById('admin-pin');
  if (adminPin) {
    adminPin.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        AdminModule.attemptLogin();
      }
    });
  }

  // --- Admin: acciones sobre reservas (delegación, sin datos de usuario en atributos) ---
  const bookingsList = document.getElementById('admin-bookings-list');
  if (bookingsList) {
    bookingsList.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-action]');
      if (!btn || btn.disabled) return;
      const row = btn.closest('[data-id]');
      if (!row) return;
      const booking = BookingStore.get(row.getAttribute('data-id'));
      if (!booking) return;

      const action = btn.getAttribute('data-action');
      if (action === 'whatsapp') {
        const firstName = String(booking.clientName).split(" ")[0];
        window.open(whatsappClientUrl(booking, `Hola ${firstName}, soy Juan José de Arkik Productions. ¿Podemos confirmar los detalles de tu reserva ${booking.code}?`), '_blank', 'noopener');
        return;
      }
      if (action === 'receipt') {
        const firstName = String(booking.clientName).split(" ")[0];
        window.open(whatsappClientUrl(booking, `Hola ${firstName}, para confirmar tu reserva ${booking.code} por favor envíame el comprobante SINPE (ref: ${booking.sinpeRef || "S/N"}) por este medio. ¡Gracias!`), '_blank', 'noopener');
        return;
      }
      if (action === 'confirm') BookingStore.updateStatus(booking.code, 'confirmada');
      else if (action === 'cancel') BookingStore.updateStatus(booking.code, 'cancelada');
      else if (action === 'pending') BookingStore.updateStatus(booking.code, 'pendiente');

      AdminModule.renderOwner();
      showToast(`Reserva ${booking.code} actualizada.`, 'success');
    });
  }

  // --- Admin: filtros de estado ---
  const statusFilters = document.getElementById('admin-status-filters');
  if (statusFilters) {
    statusFilters.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-filter]');
      if (!btn) return;
      AdminModule.ownerFilter = btn.getAttribute('data-filter');
      AdminModule.renderOwner();
    });
  }

  // --- Admin IT: pestañas, disponibilidad, precios y respaldo (delegación) ---
  const itView = document.getElementById('admin-it-view');
  if (itView) {
    itView.addEventListener('click', (e) => {
      const tab = e.target.closest('[data-it-tab]');
      if (tab) {
        const name = tab.getAttribute('data-it-tab');
        document.querySelectorAll('[data-it-tab]').forEach(t => {
          t.classList.toggle('admin-tab-btn--active', t === tab);
        });
        ["availability", "prices", "backup"].forEach(p => {
          const el = document.getElementById(`admin-it-${p}`);
          if (el) el.classList.toggle('hidden', p !== name);
        });
        return;
      }

      const availBtn = e.target.closest('[data-avail]');
      if (availBtn) {
        const iso = document.getElementById('admin-avail-date').value;
        if (!iso) {
          showToast('Seleccione una fecha primero.', 'error');
          return;
        }
        AvailabilityManager.set(iso, availBtn.getAttribute('data-avail'));
        showToast(`Disponibilidad actualizada para ${iso}.`, 'success');
        AdminModule.renderIT();
        return;
      }

      const removeBtn = e.target.closest('[data-avail-remove]');
      if (removeBtn) {
        AvailabilityManager.set(removeBtn.getAttribute('data-avail-remove'), 'available');
        showToast('Gestión manual eliminada.', 'success');
        AdminModule.renderIT();
        return;
      }

      if (e.target.closest('#admin-save-prices')) {
        document.querySelectorAll('[data-price]').forEach(input => {
          const key = input.getAttribute('data-price');
          const val = Number(input.value) || 0;
          if (key.startsWith('service-')) PriceManager.setServicePrice(Number(key.split('-')[1]), val);
          else PriceManager.setExtraPrice(key.split('-')[1], val);
        });
        updateSummaryPrices();
        renderCatalog(CATALOG_SERVICES, currentCatalogCategory);
        showToast('Precios actualizados en tiempo real.', 'success');
        return;
      }

      if (e.target.closest('#admin-reset-prices')) {
        PriceManager.reset();
        updateSummaryPrices();
        renderCatalog(CATALOG_SERVICES, currentCatalogCategory);
        AdminModule.renderIT();
        showToast('Precios restaurados a los originales.', 'success');
        return;
      }

      if (e.target.closest('#admin-export-backup')) {
        exportAdminBackup();
      }
    });

    itView.addEventListener('change', (e) => {
      if (e.target.id === 'admin-import-backup' && e.target.files && e.target.files[0]) {
        importAdminBackup(e.target.files[0]);
      }
      e.target.value = "";
    });
  }

  // --- Teclado global: ESC cierra modales + Ctrl+Shift+A abre administración ---
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const adminModal = document.getElementById('adminModal');
      if (adminModal && !adminModal.classList.contains('hidden')) {
        AdminModule.close();
        return;
      }
      const execModal = document.getElementById('executive-modal');
      if (execModal && !execModal.classList.contains('hidden')) {
        closeExecutiveModal();
        return;
      }
      const brandModal = document.getElementById('brand-modal');
      if (brandModal && !brandModal.classList.contains('hidden')) {
        closeBrandModal();
        return;
      }
      const modal = document.getElementById('booking-modal');
      if (modal && !modal.classList.contains('hidden')) {
        closeBookingModal();
      }
    }

    if (e.ctrlKey && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
      e.preventDefault();
      AdminModule.open();
    }
  });
}

// ---- Exportación / Importación de respaldo (rol IT) ----

function exportAdminBackup() {
  const payload = {
    app: "arkik-productions",
    version: 1,
    exportedAt: new Date().toISOString(),
    bookings: BookingStore.all(),
    availability: AvailabilityManager.all(),
    prices: PriceManager.exportData()
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `arkik-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  showToast('Base de datos exportada (JSON).', 'success');
}

function importAdminBackup(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const payload = JSON.parse(reader.result);
      if (!payload || typeof payload !== "object") throw new Error("formato inválido");
      if (payload.bookings !== undefined) BookingStore.replace(payload.bookings);
      if (payload.availability !== undefined) AvailabilityManager.replace(payload.availability);
      if (payload.prices !== undefined) PriceManager.replace(payload.prices);
      BookingStore.persist();
      AvailabilityManager.persist();
      PriceManager.persist();
      AdminModule.renderIT();
      showToast('Respaldo importado correctamente.', 'success');
    } catch (err) {
      showToast('Error: el archivo de respaldo no es válido.', 'error');
    }
  };
  reader.onerror = () => showToast('Error al leer el archivo de respaldo.', 'error');
  reader.readAsText(file);
}

// ============================================================
// 12. EXECUTIVE & BRAND LIGHTBOXES
// ============================================================

function openExecutiveModal() {
  const modal = document.getElementById('executive-modal');
  if (!modal) return;
  modal.classList.remove('hidden');
  modal.classList.add('flex');
  document.body.style.overflow = 'hidden';
}

function closeExecutiveModal() {
  const modal = document.getElementById('executive-modal');
  if (!modal) return;
  modal.classList.add('hidden');
  modal.classList.remove('flex');
  document.body.style.overflow = '';
}

function openBrandModal() {
  const modal = document.getElementById('brand-modal');
  if (!modal) return;
  modal.classList.remove('hidden');
  modal.classList.add('flex');
  document.body.style.overflow = 'hidden';
}

function closeBrandModal() {
  const modal = document.getElementById('brand-modal');
  if (!modal) return;
  modal.classList.add('hidden');
  modal.classList.remove('flex');
  document.body.style.overflow = '';
}

// ---- Admin Modal (acceso global) ----

function openAdminModal() {
  AdminModule.open();
}

function closeAdminModal() {
  AdminModule.close();
}

function attemptAdminLogin() {
  AdminModule.attemptLogin();
}

function adminLogout() {
  AdminModule.logout();
}

// ============================================================
// 13. BOOKING WIZARD (4 pasos con transiciones)
// ============================================================

let lastModalStep = 1;

function openBookingModal(serviceId) {
  resetBooking();

  cart.selectedService = CATALOG_SERVICES.find(s => s.id === serviceId) || CATALOG_SERVICES[0];
  cart.persist();

  updateModalStep(1);

  const modal = document.getElementById('booking-modal');
  modal.classList.remove('hidden');
  modal.classList.add('flex');

  showToast(`Cotizando: ${cart.selectedService.name}`);
}

function closeBookingModal() {
  const modal = document.getElementById('booking-modal');
  modal.classList.add('hidden');
  modal.classList.remove('flex');
  resetBooking();
}

function resetBooking() {
  Object.assign(cart, {
    selectedService: CATALOG_SERVICES[0] || null,
    extraHoursCount: 0,
    djHoursCount: 0,
    subwoofersCount: 0,
    province: "",
    canton: "",
    clientName: "",
    clientPhone: "",
    clientEmail: "",
    eventType: "Boda",
    selectedDate: "",
    selectedTime: "",
    address: "",
    sinpeRef: "",
    createdBooking: null,
    currentStep: 1,
    isSubmitting: false
  });
  lastModalStep = 1;
  CalendarModule.reset();

  const ids = ['client-name', 'client-phone', 'client-email', 'booking-address', 'sinpe-reference', 'website_hp'];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  const eventType = document.getElementById('event-type');
  if (eventType) eventType.value = "Boda";

  const prov = document.getElementById('booking-province');
  if (prov) prov.value = "";

  const canton = document.getElementById('booking-canton');
  if (canton) canton.innerHTML = '<option value="">Seleccione primero provincia</option>';

  const voucher = document.getElementById('voucher-view');
  const gateway = document.getElementById('sinpe-gateway-view');
  if (voucher) voucher.classList.add('hidden');
  if (gateway) gateway.classList.remove('hidden');

  cart.clearStoredState();
}

function goToStep(stepNumber) {
  if (stepNumber === 3 && !validateCalendarSelection()) return;

  if (stepNumber === 4) {
    if (isHoneypotTriggered()) return; // abortar silenciosamente (bot)
    if (!validateCalendarSelection()) { updateModalStep(2); return; }
    const form = document.getElementById('booking-form-step3');
    if (form && !form.checkValidity()) {
      form.reportValidity();
      updateModalStep(3);
      return;
    }
    if (!validateClientPhone()) { updateModalStep(3); return; }
    saveClientAndLocationValues();
  }

  cart.currentStep = stepNumber;
  cart.persist();
  updateModalStep(stepNumber);
}

function validateCalendarSelection() {
  if (!cart.selectedDate) {
    showToast('Seleccione una fecha disponible en el calendario.', 'error');
    return false;
  }
  if (!cart.selectedTime) {
    showToast('Seleccione una franja horaria de inicio.', 'error');
    return false;
  }
  return true;
}

function validateClientPhone() {
  const phoneEl = document.getElementById('client-phone');
  if (!phoneEl) return true;
  if (!isValidCRPhone(phoneEl.value)) {
    showToast('Teléfono no válido: use formato 8888-8888 o +506 8888-8888.', 'error');
    phoneEl.focus();
    return false;
  }
  return true;
}

function isHoneypotTriggered() {
  const hp = document.getElementById('website_hp');
  return Boolean(hp && hp.value && hp.value.trim() !== "");
}

function saveClientAndLocationValues() {
  cart.clientName = cleanText(document.getElementById('client-name').value, 120);
  cart.clientPhone = cleanText(document.getElementById('client-phone').value, 30);
  cart.clientEmail = cleanText(document.getElementById('client-email').value, 120);
  cart.eventType = cleanText(document.getElementById('event-type').value, 40);
  cart.province = document.getElementById('booking-province').value;
  cart.canton = document.getElementById('booking-canton').value;
  cart.address = cleanText(document.getElementById('booking-address').value, 300);
}

function updateModalStep(stepNumber) {
  const direction = stepNumber > lastModalStep ? 'forward' : 'backward';
  lastModalStep = stepNumber;

  for (let i = 1; i <= 4; i++) {
    const stepIndicator = document.getElementById(`step-indicator-${i}`);
    const stepPane = document.getElementById(`modal-step-${i}`);

    if (stepIndicator) {
      if (i === stepNumber) {
        stepIndicator.classList.add('border-purple-500', 'bg-purple-900/40', 'text-purple-300');
        stepIndicator.classList.remove('border-gray-700', 'text-gray-500');
      } else if (i < stepNumber) {
        stepIndicator.classList.add('border-emerald-500', 'bg-emerald-950/30', 'text-emerald-400');
        stepIndicator.classList.remove('border-purple-500', 'border-gray-700', 'text-gray-500');
      } else {
        stepIndicator.classList.remove('border-purple-500', 'bg-purple-900/40', 'text-purple-300', 'border-emerald-500', 'text-emerald-400');
        stepIndicator.classList.add('border-gray-700', 'text-gray-500');
      }
    }

    if (stepPane) {
      if (i === stepNumber) {
        stepPane.classList.remove('hidden');
        animateStepPane(stepPane, direction);
      } else {
        stepPane.classList.add('hidden');
      }
    }
  }

  if (stepNumber === 2) CalendarModule.init();

  if (stepNumber === 3) {
    const summary = document.getElementById('step3-date-time');
    if (summary) {
      summary.textContent = cart.selectedDate && cart.selectedTime
        ? `${cart.selectedDate} · ${cart.selectedTime}`
        : "Pendiente de selección";
    }
  }

  if (stepNumber === 4) {
    const gateway = document.getElementById('sinpe-gateway-view');
    const voucher = document.getElementById('voucher-view');
    if (gateway && voucher) {
      if (cart.createdBooking) {
        gateway.classList.add('hidden');
        voucher.classList.remove('hidden');
      } else {
        voucher.classList.add('hidden');
        gateway.classList.remove('hidden');
      }
    }
  }

  if (cart.selectedService) {
    document.getElementById('modal-service-name').textContent = cart.selectedService.name;
    document.getElementById('modal-service-price').textContent = `₡${PriceManager.getServicePrice(cart.selectedService).toLocaleString('es-CR')}`;
    document.getElementById('modal-service-desc').textContent = cart.selectedService.description;

    renderDynamicExtrasCounters();
    updateSummaryPrices();
  }
}

function animateStepPane(pane, direction) {
  pane.classList.remove('animate-step-in', 'animate-step-in-back');
  void pane.offsetWidth;
  pane.classList.add(direction === 'forward' ? 'animate-step-in' : 'animate-step-in-back');
}

// ---- Extras Counters (con precios dinámicos del rol IT) ----

function renderDynamicExtrasCounters() {
  const container = document.getElementById('extras-container');
  if (!container) return;

  const extraHourPrice = cart.extraHoursUnitPrice;
  const djPrice = PriceManager.getExtraPrice('dj_service');
  const subPrice = PriceManager.getExtraPrice('subwoofers');

  container.innerHTML = [
    counterRow({
      key: 'extraHoursCount',
      name: 'Hora(s) Adicional(es) de Show',
      badge: '50% del Base',
      badgeClass: 'bg-purple-900/60 text-purple-300 border border-purple-500/40',
      priceText: `₡${extraHourPrice.toLocaleString('es-CR')} por hora adicional (50% de ₡${PriceManager.getServicePrice(cart.selectedService).toLocaleString('es-CR')}) — máx. ${MAX_EXTRAS.extraHoursCount}`,
      value: cart.extraHoursCount,
      max: MAX_EXTRAS.extraHoursCount
    }),
    counterRow({
      key: 'djHoursCount',
      name: 'Servicio de DJ para Recesos',
      badge: `₡${djPrice.toLocaleString('es-CR')} / hr`,
      badgeClass: 'text-pink-400',
      priceText: 'Música continua y mezcla en vivo durante descansos',
      value: cart.djHoursCount,
      max: MAX_EXTRAS.djHoursCount
    }),
    counterRow({
      key: 'subwoofersCount',
      name: 'Subwoofers Extra de 18"',
      badge: `₡${subPrice.toLocaleString('es-CR')} / un`,
      badgeClass: 'text-pink-400',
      priceText: 'Potencia adicional de bajos para salones grandes o al aire libre',
      value: cart.subwoofersCount,
      max: MAX_EXTRAS.subwoofersCount
    })
  ].join('');
}

function counterRow({ key, name, badge, badgeClass, priceText, value, max }) {
  const atMin = value <= 0;
  const atMax = value >= max;
  const btnBase = "w-8 h-8 rounded-lg bg-purple-900/40 border border-purple-500/30 text-purple-300 font-bold flex items-center justify-center text-lg transition-all";
  const btnDisabled = " opacity-30 cursor-not-allowed";
  return `
    <div class="p-4 rounded-xl glass-panel border border-purple-500/30 flex items-center justify-between">
      <div>
        <div class="flex items-center space-x-2">
          <span class="text-sm font-bold text-white">${sanitizeHTML(name)}</span>
          <span class="text-[10px] font-extrabold px-2 py-0.5 rounded ${badgeClass}">${sanitizeHTML(badge)}</span>
        </div>
        <p class="text-xs text-gray-400 mt-0.5">${sanitizeHTML(priceText)}</p>
      </div>
      <div class="flex items-center space-x-3">
        <button type="button" onclick="adjustExtra('${key}', -1)" ${atMin ? "disabled" : ""} class="${btnBase}${atMin ? btnDisabled : ""}" aria-label="Disminuir ${sanitizeHTML(name)}">-</button>
        <span class="text-base font-extrabold text-white w-6 text-center">${value}</span>
        <button type="button" onclick="adjustExtra('${key}', 1)" ${atMax ? "disabled" : ""} class="${btnBase}${atMax ? btnDisabled : ""}" aria-label="Aumentar ${sanitizeHTML(name)}">+</button>
      </div>
    </div>
  `;
}

function adjustExtra(key, delta) {
  const current = cart[key] || 0;
  const max = MAX_EXTRAS[key] ?? Infinity;
  const newValue = Math.min(max, Math.max(0, current + delta));
  cart[key] = newValue;

  renderDynamicExtrasCounters();
  updateSummaryPrices();
  cart.persist();

  if (delta > 0) {
    showToast(newValue >= max ? `Máximo de ${max} alcanzado` : "Cotización actualizada (+)");
  }
}

// ---- Resumen de precios reactivo (con micro-animación de pulso neón) ----

function updateSummaryPrices() {
  document.querySelectorAll('.calc-subtotal').forEach(el => {
    setPriceText(el, `₡${cart.subtotal.toLocaleString('es-CR')}`);
  });

  document.querySelectorAll('.calc-gran-total').forEach(el => {
    setPriceText(el, `₡${cart.granTotal.toLocaleString('es-CR')}`);
  });

  document.querySelectorAll('.calc-deposit-50').forEach(el => {
    el.textContent = `₡${cart.deposit50Amount.toLocaleString('es-CR')}`;
  });

  document.querySelectorAll('.calc-remaining-50').forEach(el => {
    el.textContent = `₡${cart.remainingBalance.toLocaleString('es-CR')}`;
  });

  updateSurchargeBox();
}

function updateSurchargeBox() {
  const box = document.getElementById('surcharge-notice-box');
  if (!box) return;
  box.innerHTML = '';

  const div = document.createElement('div');
  div.className = 'p-3 rounded-xl border text-xs flex justify-between items-center gap-3';
  const label = document.createElement('span');
  const value = document.createElement('span');
  value.className = 'font-bold';

  if (!cart.province) {
    div.classList.add('bg-gray-950/40', 'border-gray-600/40', 'text-gray-400');
    label.textContent = 'Seleccione su provincia para calcular los viáticos de transporte:';
    value.textContent = 'Pendiente';
  } else if (!GAM_PROVINCES.includes(cart.province)) {
    div.classList.add('bg-amber-950/40', 'border-amber-500/40', 'text-amber-300');
    label.textContent = `Recargo del 12% por viáticos fuera del GAM (${cart.province}):`;
    value.textContent = `+₡${cart.travelSurcharge.toLocaleString('es-CR')}`;
  } else if (!cart.canton) {
    div.classList.add('bg-gray-950/40', 'border-gray-600/40', 'text-gray-300');
    label.textContent = `${cart.province} está dentro del GAM — seleccione el cantón para confirmar cobertura:`;
    value.textContent = 'Pendiente';
  } else if (cart.isNonGam) {
    div.classList.add('bg-amber-950/40', 'border-amber-500/40', 'text-amber-300');
    label.textContent = `Recargo del 12% por viáticos fuera del GAM (${cart.canton}, ${cart.province}):`;
    value.textContent = `+₡${cart.travelSurcharge.toLocaleString('es-CR')}`;
  } else {
    div.classList.add('bg-emerald-950/40', 'border-emerald-500/40', 'text-emerald-300');
    label.textContent = `✓ Cobertura GAM (${cart.canton}, ${cart.province}):`;
    value.textContent = '₡0 (Gratis)';
  }

  box.appendChild(div);
  div.appendChild(label);
  div.appendChild(value);
}

// ---- Provincias & Cantones ----

function populateProvinces() {
  const provSelect = document.getElementById('booking-province');
  if (!provSelect) return;
  provSelect.innerHTML = '<option value="">Seleccione Provincia...</option>' +
    Object.keys(PROVINCES_AND_CANTONES).map(p => `<option value="${sanitizeHTML(p)}">${sanitizeHTML(p)}</option>`).join('');
}

function populateCantones(province) {
  const cantonSelect = document.getElementById('booking-canton');
  if (!cantonSelect) return;

  const list = (province && PROVINCES_AND_CANTONES[province]) ? PROVINCES_AND_CANTONES[province] : [];
  cantonSelect.innerHTML = '<option value="">Seleccione Cantón...</option>' +
    list.map(c => `<option value="${sanitizeHTML(c)}">${sanitizeHTML(c)}</option>`).join('');
}

// ---- Restauración de carrito tras refresh ----

function restoreBookingToUI() {
  if (!cart.province && !cart.canton && !cart.selectedDate && !cart.clientName) return;

  populateProvinces();
  const prov = document.getElementById('booking-province');
  if (prov && cart.province) {
    prov.value = cart.province;
    populateCantones(cart.province);
    const canton = document.getElementById('booking-canton');
    if (canton && cart.canton) canton.value = cart.canton;
  }

  setField('client-name', cart.clientName);
  setField('client-phone', cart.clientPhone);
  setField('client-email', cart.clientEmail);
  setField('event-type', cart.eventType);
  setField('booking-address', cart.address);
  setField('sinpe-reference', cart.sinpeRef);

  if (cart.selectedDate) CalendarModule.init();

  updateSummaryPrices();
}

// ============================================================
// 14. FINALIZACIÓN DE RESERVA (voucher + WhatsApp + registro)
// ============================================================

function submitStaticBooking() {
  if (cart.isSubmitting) return;

  if (isHoneypotTriggered()) return; // abort silencioso anti-bot

  if (!cart.clientName || !cart.clientPhone || !cart.selectedDate || !cart.selectedTime || !cart.province || !cart.canton) {
    showToast('Faltan datos obligatorios del evento. Complete el flujo de reserva.', 'error');
    return;
  }

  const btn = document.getElementById('btn-submit-booking');
  const originalLabel = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = 'Generando voucher…';
  }
  cart.isSubmitting = true;

  cart.sinpeRef = cleanSinpeRef(document.getElementById('sinpe-reference').value);

  // Código único criptográfico (crypto.randomUUID)
  const bookingCode = generateBookingCode();

  const extrasList = [];
  if (cart.extraHoursCount > 0) extrasList.push(`• Horas Extras: ${cart.extraHoursCount} hr(s) (₡${cart.extraHoursTotal.toLocaleString('es-CR')})`);
  if (cart.djHoursCount > 0) extrasList.push(`• DJ Recesos: ${cart.djHoursCount} hr(s) (₡${cart.djTotal.toLocaleString('es-CR')})`);
  if (cart.subwoofersCount > 0) extrasList.push(`• Subwoofers 18": ${cart.subwoofersCount} un(es) (₡${cart.subwoofersTotal.toLocaleString('es-CR')})`);

  const extrasFormatted = extrasList.length > 0 ? extrasList.join('\n') : '• Ninguno';

  const surchargeText = cart.isNonGam
    ? `🚚 *Viáticos (12% fuera GAM):* ₡${cart.travelSurcharge.toLocaleString('es-CR')}`
    : `🚚 *Viáticos (GAM):* ₡0 (Sin Recargo)`;

  const rawMsg =
`🎸 *ARKIK PRODUCTIONS - RESERVA & COTIZACIÓN*
----------------------------------------
📌 *Código:* ${bookingCode}
👤 *Cliente:* ${cart.clientName}
📞 *Teléfono:* ${cart.clientPhone}
✉️ *Email:* ${cart.clientEmail}
🎉 *Tipo de Evento:* ${cart.eventType}

🎵 *Formato:* ${cart.selectedService.name} (₡${PriceManager.getServicePrice(cart.selectedService).toLocaleString('es-CR')})
⏱️ *Duración:* ${cart.selectedService.duration}

➕ *EXTRAS COTIZADOS:*
${extrasFormatted}

📅 *Fecha & Hora:* ${cart.selectedDate} @ ${cart.selectedTime}
📍 *Ubicación:* ${cart.canton}, ${cart.province}
🏠 *Dirección:* ${cart.address}

💰 *Subtotal:* ₡${cart.subtotal.toLocaleString('es-CR')}
${surchargeText}
✨ *GRAN TOTAL:* ₡${cart.granTotal.toLocaleString('es-CR')}
----------------------------------------
💳 *ADELANTO SINPE (50%):* ₡${cart.deposit50Amount.toLocaleString('es-CR')}
🤝 *SALDO DÍA DEL EVENTO:* ₡${cart.remainingBalance.toLocaleString('es-CR')}
📲 *Destino SINPE:* ${SINPE_CONFIG.phone} (${SINPE_CONFIG.holder})
🔢 *Ref. SINPE:* ${cart.sinpeRef}
----------------------------------------
📎 *Importante:* Realice el SINPE por el 50% y envíe el comprobante como adjunto directamente en este chat para confirmar su reserva.`;

  const encodedMsg = encodeURIComponent(rawMsg);
  const whatsappUrl = `https://wa.me/${SINPE_CONFIG.cleanPhone}?text=${encodedMsg}`;

  // Registro persistente en la base local (dashboard del Propietario)
  const record = {
    code: bookingCode,
    createdAt: new Date().toISOString(),
    status: "pendiente",
    clientName: cart.clientName,
    clientPhone: cart.clientPhone,
    clientEmail: cart.clientEmail,
    eventType: cart.eventType,
    serviceId: cart.selectedService.id,
    serviceName: cart.selectedService.name,
    selectedDate: cart.selectedDate,
    selectedTime: cart.selectedTime,
    province: cart.province,
    canton: cart.canton,
    address: cart.address,
    extras: {
      extraHoursCount: cart.extraHoursCount,
      djHoursCount: cart.djHoursCount,
      subwoofersCount: cart.subwoofersCount,
      extraHoursTotal: cart.extraHoursTotal,
      djTotal: cart.djTotal,
      subwoofersTotal: cart.subwoofersTotal
    },
    subtotal: cart.subtotal,
    travelSurcharge: cart.travelSurcharge,
    granTotal: cart.granTotal,
    deposit50Amount: cart.deposit50Amount,
    remainingBalance: cart.remainingBalance,
    sinpeRef: cart.sinpeRef
  };
  BookingStore.add(record);
  cart.createdBooking = record;

  // Voucher: solo textContent, ningún dato de usuario entra por innerHTML
  document.getElementById('confirm-booking-code').textContent = bookingCode;
  document.getElementById('confirm-client-name').textContent = cart.clientName;
  document.getElementById('confirm-event-type').textContent = cart.eventType;
  document.getElementById('confirm-service-name').textContent = cart.selectedService.name;
  document.getElementById('confirm-event-date').textContent = `${cart.selectedDate} - ${cart.selectedTime}`;
  document.getElementById('confirm-location').textContent = `${cart.canton}, ${cart.province}`;
  document.getElementById('confirm-gran-total').textContent = `₡${cart.granTotal.toLocaleString('es-CR')}`;
  document.getElementById('confirm-deposit-50').textContent = `₡${cart.deposit50Amount.toLocaleString('es-CR')}`;

  const waBtn = document.getElementById('btn-whatsapp-client');
  if (waBtn) {
    waBtn.href = whatsappUrl;
  }

  // Borrar borrador persistido: un refresh nunca duplica la reserva
  cart.clearStoredState();

  cart.isSubmitting = false;
  if (btn) {
    btn.disabled = false;
    btn.innerHTML = originalLabel;
  }

  goToStep(4);
  showToast('¡Voucher y enlace de WhatsApp generados!', 'success');
}

function finalizeVoucher() {
  closeBookingModal();
  showToast('¡Reserva registrada! Revisaremos su comprobante SINPE.', 'success');
}

// ============================================================
// 15. TOAST NOTIFICATIONS (sin innerHTML con datos de usuario)
// ============================================================

function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast-item';
  if (type === 'error') toast.classList.add('toast-error');
  if (type === 'success') toast.classList.add('toast-success');

  const icons = {
    success: '<svg class="w-5 h-5 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>',
    error: '<svg class="w-5 h-5 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>',
    info: '<svg class="w-5 h-5 text-purple-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
  };

  const iconWrap = document.createElement('span');
  iconWrap.className = 'flex-shrink-0';
  iconWrap.innerHTML = icons[type] || icons.info;

  const text = document.createElement('span');
  text.className = 'text-xs font-semibold';
  text.textContent = message;

  toast.appendChild(iconWrap);
  toast.appendChild(text);
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-out');
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

// ---- Utilidades de portapapeles ----

function copySinpeNumber(btn) {
  const CLIPBOARD_ICON =
    '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>';
  const CHECK_ICON =
    '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>';

  const done = () => {
    showToast("¡Número SINPE copiado!", "success");
    if (btn) {
      btn.innerHTML = CHECK_ICON;
      btn.disabled = true;
      setTimeout(() => {
        btn.innerHTML = CLIPBOARD_ICON;
        btn.disabled = false;
      }, 1500);
    }
  };
  const fail = () => showToast("No se pudo copiar el número automáticamente.", "error");

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(SINPE_CONFIG.phone).then(done).catch(fail);
  } else {
    try {
      const ta = document.createElement('textarea');
      ta.value = SINPE_CONFIG.phone;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      ok ? done() : fail();
    } catch (err) {
      fail();
    }
  }
}

function copyBookingCode() {
  const codeEl = document.getElementById('confirm-booking-code');
  if (!codeEl) return;

  const text = codeEl.textContent;
  const done = () => showToast(`Código ${text} copiado al portapapeles.`, 'success');
  const fail = () => showToast('No se pudo copiar el código automáticamente.', 'error');

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(fail);
  } else {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      ok ? done() : fail();
    } catch (err) {
      fail();
    }
  }
}

// ============================================================
// 16. FOOTER: FLUID NEON WAVE ENGINE (Canvas 2D, 60 FPS)
// ============================================================

function initFooterFluidEffect() {
  const footer = document.getElementById('site-footer');
  const canvas = document.getElementById('footerFluidCanvas');
  if (!footer || !canvas) return;

  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const DPR_CAP = 2;
  const NEON = ['#a855f7', '#38bdf8', '#10b981', '#ec4899'];
  const RIBBON_COUNT = 3;
  const RIBBON_POINTS = 64;
  const MAX_PARTICLES = 140;

  let W = 0;
  let H = 0;
  let rafId = null;
  let footerInView = false;
  let lastBurstAt = 0;
  let lastScrollAt = 0;
  const ribbons = [];
  const particles = [];

  function buildRibbons() {
    ribbons.length = 0;
    for (let i = 0; i < RIBBON_COUNT; i++) {
      ribbons.push({
        color: NEON[i % NEON.length],
        baseY: (0.28 + i * 0.2 + Math.random() * 0.12) * H,
        amp: (0.02 + Math.random() * 0.018) * H,
        freq: 0.004 + Math.random() * 0.003,
        speed: 0.00022 + Math.random() * 0.00018,
        phase: Math.random() * Math.PI * 2,
        width: 1.6 + Math.random() * 1.4,
        alpha: 0.34 + Math.random() * 0.2
      });
    }
  }

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
    const rect = footer.getBoundingClientRect();
    W = Math.max(1, Math.round(rect.width * dpr));
    H = Math.max(1, Math.round(rect.height * dpr));
    canvas.width = W;
    canvas.height = H;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    buildRibbons();
  }

  function spawnBurst(x, y, count, spread) {
    if (particles.length >= MAX_PARTICLES) return;
    for (let i = 0; i < count; i++) {
      if (particles.length >= MAX_PARTICLES) break;
      const angle = Math.random() * Math.PI * 2;
      const speed = 0.5 + Math.random() * 2.2;
      const life = 700 + Math.random() * 900;
      particles.push({
        x: x + (Math.random() - 0.5) * spread,
        y: y + (Math.random() - 0.5) * spread,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        life,
        maxLife: life,
        size: 1 + Math.random() * 1.6,
        color: NEON[Math.floor(Math.random() * NEON.length)],
        history: []
      });
    }
  }

  function pointerBurst(e) {
    const now = performance.now();
    if (now - lastBurstAt < 70) return;
    lastBurstAt = now;
    const rect = footer.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    if (x < 0 || y < 0 || x > rect.width || y > rect.height) return;
    spawnBurst(x, y, 5, 26);
  }

  function scrollBurst() {
    if (!footerInView) return;
    const now = performance.now();
    if (now - lastScrollAt < 260) return;
    lastScrollAt = now;
    const rect = footer.getBoundingClientRect();
    for (let i = 0; i < 3; i++) {
      spawnBurst(Math.random() * rect.width, rect.top * 0.2 + Math.random() * rect.height * 0.25, 4, 40);
    }
  }

  function tick() {
    ctx.clearRect(0, 0, W, H);

    for (const r of ribbons) {
      ctx.beginPath();
      for (let i = 0; i <= RIBBON_POINTS; i++) {
        const x = (i / RIBBON_POINTS) * W;
        const y = r.baseY
          + Math.sin(x * r.freq + performance.now() * r.speed + r.phase) * r.amp
          + Math.sin(x * r.freq * 2.7 - performance.now() * r.speed * 0.6 + r.phase * 2) * r.amp * 0.35;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = r.color;
      ctx.globalAlpha = r.alpha;
      ctx.lineWidth = r.width;
      ctx.shadowBlur = 16;
      ctx.shadowColor = r.color;
      ctx.stroke();
    }

    ctx.shadowBlur = 12;
    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;
      p.vx *= 0.985;
      p.vy *= 0.985;
      p.life -= 16.67;
      p.history.push({ x: p.x, y: p.y });
      if (p.history.length > 7) p.history.shift();
      if (p.life <= 0 || p.y > H + 30) {
        particles.splice(i, 1);
        continue;
      }
      const alpha = Math.max(0, p.life / p.maxLife) * 0.8;
      ctx.strokeStyle = p.color;
      ctx.globalAlpha = alpha;
      ctx.lineWidth = p.size;
      ctx.shadowColor = p.color;
      ctx.beginPath();
      p.history.forEach((pt, idx) => {
        if (idx === 0) ctx.moveTo(pt.x, pt.y);
        else ctx.lineTo(pt.x, pt.y);
      });
      ctx.stroke();
    }

    ctx.globalAlpha = 1;
    ctx.shadowBlur = 0;

    rafId = requestAnimationFrame(tick);
  }

  function start() {
    if (rafId != null || reducedMotion) return;
    rafId = requestAnimationFrame(tick);
  }

  function stop() {
    if (rafId == null) return;
    cancelAnimationFrame(rafId);
    rafId = null;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      footerInView = entry.isIntersecting;
      footerInView ? start() : stop();
    });
  }, { rootMargin: '120px' });
  observer.observe(footer);

  footer.addEventListener('pointermove', pointerBurst, { passive: true });
  window.addEventListener('scroll', scrollBurst, { passive: true });

  resize();
  start();
  window.addEventListener('resize', resize);
}

// ============================================================
// 17. HERO: CUERDAS DE GUITARRA NEÓN INTERACTIVAS (Canvas 2D)
// ============================================================

function initHeroStringsEffect() {
  const hero = document.getElementById('hero');
  const canvas = document.getElementById('heroStringsCanvas');
  if (!hero || !canvas) return;

  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const DPR_CAP = 2;
  const NEON = ['#a855f7', '#38bdf8', '#10b981', '#ec4899'];
  const STRING_COUNT = 4;
  const SEGMENTS = 60;
  const DEFLECT_REACH = 140;

  let W = 0;
  let H = 0;
  let rafId = null;
  let heroInView = false;
  const strings = [];
  let scrollEnergy = 0;
  let lastScrollY = window.scrollY || 0;
  let lastScrollAt = performance.now();
  const pointer = { x: -1, y: -1, active: false, velX: 0, velY: 0, lastX: -1, lastY: -1, lastT: 0 };

  function buildStrings() {
    strings.length = 0;
    for (let i = 0; i < STRING_COUNT; i++) {
      strings.push({
        color: NEON[i % NEON.length],
        baseY: (0.16 + i * 0.22 + Math.random() * 0.04) * H,
        amp: (0.008 + Math.random() * 0.006) * H,
        freq: 0.006 + Math.random() * 0.004,
        speed: 0.0002 + Math.random() * 0.0002,
        phase: Math.random() * Math.PI * 2,
        width: i === 2 ? 2 : 1.5,
        alpha: i === 3 ? 0.55 : 0.85
      });
    }
  }

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
    const rect = hero.getBoundingClientRect();
    W = Math.max(1, Math.round(rect.width * dpr));
    H = Math.max(1, Math.round(rect.height * dpr));
    canvas.width = W;
    canvas.height = H;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    buildStrings();
  }

  function onScroll() {
    const now = performance.now();
    const sy = window.scrollY || 0;
    const dt = Math.max(1, now - lastScrollAt);
    const velocity = Math.abs(sy - lastScrollY) / dt;
    lastScrollY = sy;
    lastScrollAt = now;
    if (!heroInView || velocity <= 0.4) return;
    scrollEnergy = Math.min(1, scrollEnergy + Math.min(0.5, velocity * 0.004));
  }

  function onPointerMove(e) {
    const rect = hero.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    if (x < -60 || y < -60 || x > rect.width + 60 || y > rect.height + 60) {
      pointer.active = false;
      return;
    }
    const now = performance.now();
    if (pointer.lastX >= 0 && now > pointer.lastT) {
      pointer.velX = (x - pointer.lastX) / (now - pointer.lastT);
      pointer.velY = (y - pointer.lastY) / (now - pointer.lastT);
    }
    pointer.x = x;
    pointer.y = y;
    pointer.active = true;
    pointer.lastX = x;
    pointer.lastY = y;
    pointer.lastT = now;
  }

  function onPointerLeave() {
    pointer.active = false;
  }

  function tick() {
    ctx.clearRect(0, 0, W, H);
    const t = performance.now();

    scrollEnergy *= 0.94;
    if (scrollEnergy < 0.004) scrollEnergy = 0;

    for (let s = 0; s < strings.length; s++) {
      const st = strings[s];
      ctx.beginPath();
      ctx.shadowBlur = 14;
      ctx.shadowColor = st.color;
      ctx.strokeStyle = st.color;
      ctx.globalAlpha = st.alpha;
      ctx.lineWidth = st.width;
      ctx.lineCap = 'round';

      for (let i = 0; i <= SEGMENTS; i++) {
        const fx = i / SEGMENTS;
        const x = fx * W;

        let y = st.baseY
          + Math.sin(x * st.freq + t * st.speed + st.phase) * st.amp
          + Math.sin(x * st.freq * 2.3 - t * st.speed * 0.55 + st.phase * 2.1) * st.amp * 0.4;

        if (scrollEnergy > 0) {
          const travel = (t * 0.0006) % 1;
          const d = Math.abs(fx - travel);
          const envelope = d < 0.5 ? Math.cos((d / 0.5) * Math.PI) : 0;
          y += Math.sin(d * Math.PI * 6 - t * 0.004) * envelope * scrollEnergy * 26;
        }

        if (pointer.active) {
          const dx = x - pointer.x;
          const dy = pointer.y - st.baseY;
          if (Math.abs(dx) < DEFLECT_REACH) {
            const g = Math.exp(-(dx * dx) / (2 * 38 * 38));
            const pull = Math.exp(-(dy * dy) / (2 * 62 * 62));
            const velBoost = Math.min(1.4, 1 + (Math.abs(pointer.velX) + Math.abs(pointer.velY)) * 0.02);
            y += Math.sign(dy) * g * pull * 32 * velBoost;
          }
        }

        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
    }

    ctx.globalAlpha = 1;
    ctx.shadowBlur = 0;

    rafId = requestAnimationFrame(tick);
  }

  function start() {
    if (rafId != null || reducedMotion) return;
    rafId = requestAnimationFrame(tick);
  }

  function stop() {
    if (rafId == null) return;
    cancelAnimationFrame(rafId);
    rafId = null;
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      heroInView = entry.isIntersecting;
      heroInView ? start() : stop();
    });
  }, { rootMargin: '120px' });
  observer.observe(hero);

  window.addEventListener('scroll', onScroll, { passive: true });
  hero.addEventListener('mousemove', onPointerMove, { passive: true });
  hero.addEventListener('touchstart', onPointerMove, { passive: true });
  hero.addEventListener('touchmove', onPointerMove, { passive: true });
  hero.addEventListener('mouseleave', onPointerLeave);
  hero.addEventListener('touchend', onPointerLeave, { passive: true });

  resize();
  start();
  window.addEventListener('resize', resize);
}