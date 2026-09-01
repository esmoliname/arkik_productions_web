// Arkik Productions - Elite Architecture, Security Shielding, Availability Calendar & PDF Engine (2026)

// ============================================================
// 0. SECURITY & SANITIZATION LAYER (Capa Global Anti-XSS y Anti-Inyección)
// ============================================================

/**
 * Escapa caracteres peligrosos para evitar Cross-Site Scripting (XSS).
 * Ningún dato de usuario entra al DOM sin pasar por sanitización o textContent.
 */
function sanitizeInput(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/\//g, "&#47;");
}

const sanitizeHTML = sanitizeInput; // alias para compatibilidad interna

/**
 * Sanitiza URLs para prevenir ataques javascript: y XSS en atributos href/src.
 */
function sanitizeUrl(url) {
  if (!url || typeof url !== "string") return "#";
  const trimmed = url.trim();
  if (/^(https?:\/\/|\/|\.\/|img\/)/i.test(trimmed)) {
    return trimmed.replace(/"/g, "%22").replace(/'/g, "%27").replace(/</g, "%3C").replace(/>/g, "%3E");
  }
  return "#";
}

// Hash FNV-1a de respaldo (en caso de que crypto.subtle no esté disponible)
function fnv1aHex(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return ("00000000" + (h >>> 0).toString(16)).slice(-8);
}

// SHA-256 con WebCrypto (contexto seguro con fallback)
async function sha256Hex(text) {
  try {
    if (window.crypto && window.crypto.subtle) {
      const buf = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    }
  } catch (err) {
    /* fallback a fnv1a */
  }
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
  } catch (err) {
    /* storage no disponible */
  }
}

// ============================================================
// 1. PURE HELPERS & REGEX VALIDATORS
// ============================================================

function clampInt(value, min, max) {
  const n = parseInt(value, 10);
  if (Number.isNaN(n)) return min;
  return Math.min(max, Math.max(min, n));
}

function cleanText(value, maxLen) {
  return typeof value === "string" ? value.trim().slice(0, maxLen) : "";
}

// Validación estricta de teléfonos Costa Rica: 8 dígitos con prefijo opcional (+506 o 506)
function isValidCRPhone(phone) {
  return /^(\+?506)?\s?[2678]\d{3}[-\s]?\d{4}$/.test(String(phone || "").trim());
}

// Validación estándar RFC 5322 de correo electrónico
function isValidRFC5322Email(email) {
  const regex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  return regex.test(String(email || "").trim());
}

// Referencia SINPE: estricta sanitización alfanumérica (máx 15 caracteres)
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

// Normaliza teléfono CR a formato internacional para wa.me (506XXXXXXXX)
function normalizeWaPhone(phone) {
  let digits = String(phone || "").replace(/\D/g, "");
  if (digits.length === 8) digits = "506" + digits;
  return digits;
}

// Códigos únicos criptográficos: ARK-XXXXXXXX (8 caracteres alfanuméricos en mayúsculas)
function generateBookingCode() {
  try {
    if (window.crypto && window.crypto.randomUUID) {
      const raw = window.crypto.randomUUID().replace(/-/g, "").toUpperCase();
      return `ARK-${raw.slice(0, 8)}`;
    }
  } catch (err) {
    /* fallback */
  }
  const randomHex = Math.random().toString(36).substring(2, 10).toUpperCase();
  return `ARK-${randomHex.padEnd(8, "X")}`;
}

function formatCRC(n) {
  return `₡${Number(n || 0).toLocaleString("es-CR")}`;
}

function setField(id, value) {
  const el = document.getElementById(id);
  if (el && value !== undefined && value !== null) el.value = value;
}

function setPriceText(el, text) {
  if (!el || el.textContent === text) return;
  el.textContent = text;
  el.classList.remove("price-pulse");
  void el.offsetWidth;
  el.classList.add("price-pulse");
}

// ============================================================
// 2. STORAGE ENGINE (Motor Centralizado de Persistencia, Hidratación & CRUD)
// ============================================================

const StorageEngine = {
  _gallery: null,
  _config: null,

  init() {
    try { PriceManager.load(); } catch (e) { console.warn('PriceManager.load failed:', e); }
    try { AvailabilityManager.load(); } catch (e) { console.warn('AvailabilityManager.load failed:', e); }
    try { BookingStore.load(); } catch (e) { console.warn('BookingStore.load failed:', e); }
    try { this.loadGallery(); } catch (e) { console.warn('StorageEngine.loadGallery failed:', e); }
    try { this.loadConfig(); } catch (e) { console.warn('StorageEngine.loadConfig failed:', e); }
  },

  loadGallery() {
    const stored = safeParse(STORAGE_KEYS.gallery, null);
    if (Array.isArray(stored) && stored.length > 0) {
      this._gallery = stored;
    } else {
      this._gallery = JSON.parse(JSON.stringify(mediaLibrary));
      this.persistGallery();
    }
  },

  persistGallery() {
    safeSet(STORAGE_KEYS.gallery, this._gallery);
  },

  getGalleryItems() {
    if (!this._gallery) this.loadGallery();
    return this._gallery;
  },

  setGalleryItems(items) {
    this._gallery = Array.isArray(items) ? items : [];
    this.persistGallery();
    this.onDataChange("gallery");
  },

  addGalleryItem(item) {
    const newItem = {
      id: "media-" + Date.now().toString(36),
      title: sanitizeInput(cleanText(item.title, 100)),
      category: item.category || "instagram",
      type: item.type || "instagram",
      embedUrl: sanitizeUrl(item.embedUrl || ""),
      directUrl: sanitizeUrl(item.directUrl || "https://www.instagram.com/kikeramirezcr"),
      url: sanitizeUrl(item.directUrl || item.url || "https://www.instagram.com/kikeramirezcr"),
      thumbnail: sanitizeUrl(item.thumbnail || "img/Foto Kike .jpg"),
      caption: sanitizeInput(cleanText(item.caption || "", 300)),
      subtitle: sanitizeInput(cleanText(item.caption || item.subtitle || "", 300)),
      date: sanitizeInput(cleanText(item.date || "2026", 30)),
      featured: Boolean(item.featured)
    };
    if (!this._gallery) this.loadGallery();
    this._gallery.unshift(newItem);
    this.persistGallery();
    this.onDataChange("gallery");
    return newItem;
  },

  updateGalleryItem(id, item) {
    if (!this._gallery) this.loadGallery();
    const index = this._gallery.findIndex(m => String(m.id) === String(id));
    if (index === -1) return false;
    this._gallery[index] = {
      ...this._gallery[index],
      title: item.title !== undefined ? sanitizeInput(cleanText(item.title, 100)) : this._gallery[index].title,
      category: item.category || this._gallery[index].category,
      type: item.type || this._gallery[index].type,
      embedUrl: sanitizeUrl(item.embedUrl !== undefined ? item.embedUrl : this._gallery[index].embedUrl),
      directUrl: sanitizeUrl(item.directUrl || this._gallery[index].directUrl),
      url: sanitizeUrl(item.directUrl || item.url || this._gallery[index].directUrl),
      thumbnail: sanitizeUrl(item.thumbnail || this._gallery[index].thumbnail),
      caption: item.caption !== undefined ? sanitizeInput(cleanText(item.caption, 300)) : this._gallery[index].caption,
      subtitle: item.caption !== undefined ? sanitizeInput(cleanText(item.caption, 300)) : this._gallery[index].subtitle,
      date: item.date !== undefined ? sanitizeInput(cleanText(item.date, 30)) : this._gallery[index].date,
      featured: item.featured !== undefined ? Boolean(item.featured) : this._gallery[index].featured
    };
    this.persistGallery();
    this.onDataChange("gallery");
    return true;
  },

  deleteGalleryItem(id) {
    if (!this._gallery) this.loadGallery();
    this._gallery = this._gallery.filter(m => String(m.id) !== String(id));
    this.persistGallery();
    this.onDataChange("gallery");
  },

  toggleFeaturedGalleryItem(id) {
    if (!this._gallery) this.loadGallery();
    const item = this._gallery.find(m => String(m.id) === String(id));
    if (item) {
      item.featured = !item.featured;
      this.persistGallery();
      this.onDataChange("gallery");
    }
  },

  resetGalleryItems() {
    this._gallery = JSON.parse(JSON.stringify(mediaLibrary));
    this.persistGallery();
    this.onDataChange("gallery");
  },

  // Configuration management (extra multiplier, travel surcharge, custom rates)
  loadConfig() {
    this._config = safeParse(STORAGE_KEYS.customConfig, {
      extraHourMultiplier: 0.50,
      travelSurchargeRate: NON_GAM_SURCHARGE_RATE,
      subwoofersUnitPrice: DYNAMIC_EXTRAS_CONFIG.subwoofers.unitPrice,
      djUnitPrice: DYNAMIC_EXTRAS_CONFIG.dj_service.unitPrice
    });
  },

  persistConfig() {
    safeSet(STORAGE_KEYS.customConfig, this._config);
  },

  getConfig(key, fallback) {
    if (!this._config) this.loadConfig();
    return this._config && this._config[key] !== undefined ? this._config[key] : fallback;
  },

  setConfig(key, value) {
    if (!this._config) this.loadConfig();
    this._config[key] = value;
    this.persistConfig();
    this.onDataChange("config");
  },

  // Storage Telemetry
  getStorageStats() {
    let totalBytes = 0;
    const breakdown = {};
    Object.keys(STORAGE_KEYS).forEach(k => {
      const key = STORAGE_KEYS[k];
      const val = localStorage.getItem(key) || "";
      const bytes = new Blob([val]).size;
      breakdown[k] = { key, bytes, kb: (bytes / 1024).toFixed(2) };
      totalBytes += bytes;
    });
    return {
      totalBytes,
      totalKb: (totalBytes / 1024).toFixed(2),
      breakdown
    };
  },

  // Full Database Backup & Restore
  exportFullDatabase() {
    return {
      app: "arkik-productions",
      version: "3.2.0",
      exportedAt: new Date().toISOString(),
      bookings: BookingStore.all(),
      availability: AvailabilityManager.all(),
      prices: PriceManager.exportData(),
      customConfig: this._config || {},
      gallery: this.getGalleryItems(),
      audit: typeof AuditLog !== "undefined" ? AuditLog.load() : {}
    };
  },

  importFullDatabase(payload) {
    validateBackupPayload(payload);
    if (payload.bookings !== undefined && Array.isArray(payload.bookings)) {
      BookingStore.replace(payload.bookings);
    }
    if (payload.availability !== undefined && typeof payload.availability === "object") {
      AvailabilityManager.replace(payload.availability);
    }
    if (payload.prices !== undefined && typeof payload.prices === "object") {
      PriceManager.replace(payload.prices);
    }
    if (payload.gallery !== undefined && Array.isArray(payload.gallery)) {
      this.setGalleryItems(payload.gallery);
    }
    if (payload.customConfig !== undefined && typeof payload.customConfig === "object") {
      this._config = { ...this._config, ...payload.customConfig };
      this.persistConfig();
    }
    this.onDataChange("all");
  },

  // Reactive DOM dispatch
  onDataChange(source) {
    if (source === "gallery" || source === "all") {
      if (typeof renderGalleryFilters === "function") renderGalleryFilters(typeof currentGalleryFilter !== "undefined" ? currentGalleryFilter : "todos");
      if (typeof renderMediaGallery === "function") renderMediaGallery(this.getGalleryItems(), typeof currentGalleryFilter !== "undefined" ? currentGalleryFilter : "todos");
    }
    if (source === "prices" || source === "config" || source === "all") {
      if (typeof renderCatalog === "function") renderCatalog(CATALOG_SERVICES, typeof currentCatalogCategory !== "undefined" ? currentCatalogCategory : "Todos");
      if (typeof updateSummaryPrices === "function") updateSummaryPrices();
    }
    if (source === "availability" || source === "all") {
      if (typeof CalendarModule !== "undefined" && typeof CalendarModule.render === "function") {
        CalendarModule.render();
      }
    }
  }
};

// ============================================================
// 2.5 PRICE MANAGER (Precios dinámicos modificables en vivo por rol IT)
// ============================================================

const PriceManager = {
  _data: null,

  load() {
    try {
      this._data = safeParse(STORAGE_KEYS.prices, { services: {}, extras: {} });
      if (!this._data || typeof this._data !== "object") this._data = { services: {}, extras: {} };
    } catch (e) {
      console.warn('PriceManager.load corruption recovered:', e.message || e);
      this._data = { services: {}, extras: {} };
    }
  },

  persist() {
    safeSet(STORAGE_KEYS.prices, this._data);
  },

  getServicePrice(service) {
    if (!service) return 0;
    if (!this._data) this.load();
    const p = Number(this._data.services[service.id]);
    return Number.isFinite(p) && p > 0 ? p : service.price_crc;
  },

  getExtraPrice(key) {
    if (!this._data) this.load();
    const p = Number(this._data.extras[key]);
    if (Number.isFinite(p) && p > 0) return p;
    const cfg = DYNAMIC_EXTRAS_CONFIG[key];
    return cfg ? cfg.unitPrice : 0;
  },

  setServicePrice(id, price) {
    if (!this._data) this.load();
    this._data.services[id] = Math.max(0, Math.round(Number(price) || 0));
    this.persist();
  },

  setExtraPrice(key, price) {
    if (!this._data) this.load();
    const val = Math.max(0, Math.round(Number(price) || 0));
    if (val > 0) this._data.extras[key] = val;
    else delete this._data.extras[key];
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
    if (!this._data) this.load();
    return JSON.parse(JSON.stringify(this._data));
  }
};

// ============================================================
// 3. AVAILABILITY MANAGER (Fechas agotadas / bloqueadas / capacidad)
// ============================================================

const AvailabilityManager = {
  _data: null,

  load() {
    try {
      this._data = safeParse(STORAGE_KEYS.availability, {});
      if (!this._data || typeof this._data !== "object") this._data = {};
    } catch (e) {
      console.warn('AvailabilityManager.load corruption recovered:', e.message || e);
      this._data = {};
    }
  },

  persist() {
    safeSet(STORAGE_KEYS.availability, this._data);
  },

  get(iso) {
    if (!this._data) this.load();
    return this._data[iso] || null;
  },

  set(iso, status) {
    if (!this._data) this.load();
    if (status === "available") delete this._data[iso];
    else this._data[iso] = status;
    this.persist();
    if (typeof StorageEngine !== "undefined" && StorageEngine.onDataChange) {
      StorageEngine.onDataChange("availability");
    }
  },

  all() {
    if (!this._data) this.load();
    return JSON.parse(JSON.stringify(this._data));
  },

  remainingSlots(iso) {
    const booked = BookingStore.countForDate(iso);
    return Math.max(0, DEFAULT_MAX_EVENTS_PER_DAY - booked);
  },

  replace(payload) {
    this._data = {};
    Object.keys(payload || {}).forEach(k => {
      if (payload[k] === "soldout" || payload[k] === "disabled") this._data[k] = payload[k];
    });
  }
};

// ============================================================
// 4. BOOKING STORE (Registro persistente de reservas)
// ============================================================

const BookingStore = {
  _data: null,

  load() {
    try {
      const raw = safeParse(STORAGE_KEYS.bookings, []);
      this._data = Array.isArray(raw) ? raw : [];
    } catch (e) {
      console.warn('BookingStore.load corruption recovered:', e.message || e);
      this._data = [];
    }
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

  getBookingsForDate(iso) {
    return this._data.filter(b => b.selectedDate === iso && b.status !== "cancelada");
  },

  replace(list) {
    this._data = Array.isArray(list) ? list : [];
  }
};

// ============================================================
// 5. SECURITY MODULE (PIN hasheado + Anti fuerza bruta)
// ============================================================

const SecurityModule = {
  _data: null,

  load() {
    try {
      this._data = safeParse(STORAGE_KEYS.admin, { ownerHash: null, itHash: null, attempts: 0, lockoutUntil: 0 });
    } catch (e) {
      console.warn('SecurityModule.load corruption recovered:', e.message || e);
      this._data = { ownerHash: null, itHash: null, attempts: 0, lockoutUntil: 0 };
    }
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
// 6. CART STATE (Motor de precios, Viáticos GAM y Logística)
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
    this.address = "";
    this.sinpeRef = "";
    this.createdBooking = null;
    this.currentStep = 1;
    this.isSubmitting = false;
    this.restore();
  }

  // ---- Motor de Precios ----

  get extraHourMultiplier() {
    return (typeof StorageEngine !== "undefined" && StorageEngine.getConfig)
      ? StorageEngine.getConfig("extraHourMultiplier", 0.50)
      : 0.50;
  }

  get extraHoursUnitPrice() {
    if (!this.selectedService) return 0;
    const override = PriceManager.getExtraPrice("extra_hours");
    if (override > 0) return override;
    return Math.round(PriceManager.getServicePrice(this.selectedService) * this.extraHourMultiplier);
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

  get travelSurchargeRate() {
    return (typeof StorageEngine !== "undefined" && StorageEngine.getConfig)
      ? StorageEngine.getConfig("travelSurchargeRate", NON_GAM_SURCHARGE_RATE)
      : NON_GAM_SURCHARGE_RATE;
  }

  get travelSurcharge() {
    return this.isNonGam ? Math.round(this.subtotal * this.travelSurchargeRate) : 0;
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

  // ---- Persistencia de Carrito ----

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
      this.clientName = cleanText(data.clientName, 70);
      this.clientPhone = cleanText(data.clientPhone, 30);
      this.clientEmail = cleanText(data.clientEmail, 120);
      this.eventType = cleanText(data.eventType, 40) || "Boda";
      this.address = cleanText(data.address, 300);
      this.sinpeRef = cleanText(data.sinpeRef, 15);

      const savedDate = cleanText(data.selectedDate || data.eventDate, 10);
      if (parseISO(savedDate)) this.selectedDate = savedDate;
    } catch (err) {
      // payload corrupto
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
// 7. CALENDAR MODULE (72h lock, 365d horizon, 2 eventos/día, 5h buffer)
// ============================================================

const CalendarModule = {
  viewDate: null,
  selectedDate: "",

  init() {
    if (!cart.selectedDate) {
      this.viewDate = startOfMonth(new Date());
    } else {
      const d = parseISO(cart.selectedDate);
      this.viewDate = startOfMonth(d || new Date());
      this.selectedDate = cart.selectedDate;
    }
    this.render();
  },

  reset() {
    this.viewDate = null;
    this.selectedDate = "";
  },

  // Calcula límites de fecha según reglas operativas
  getThresholds() {
    const now = new Date();
    // 72 horas (3 días) de antelación mínima obligatoria
    const minBookingDate = new Date(now.getTime() + LOGISTICS_CONFIG.minNoticeHours * 3600 * 1000);
    const minISO = isoOf(minBookingDate);

    // 365 días horizonte máximo
    const maxBookingDate = new Date(now.getTime() + LOGISTICS_CONFIG.maxHorizonDays * 24 * 3600 * 1000);
    const maxISO = isoOf(maxBookingDate);

    return { nowISO: isoOf(now), minISO, maxISO };
  },

  render() {
    const grid = document.getElementById("calendar-grid");
    const label = document.getElementById("cal-month-label");
    const yearLabel = document.getElementById("cal-year-label");
    if (!grid) return;

    this.viewDate = this.viewDate || startOfMonth(new Date());
    const y = this.viewDate.getFullYear();
    const m = this.viewDate.getMonth();
    if (label) label.textContent = `${CALENDAR_LOCALE.months[m]} ${y}`;
    if (yearLabel) yearLabel.textContent = y;

    const { nowISO, minISO, maxISO } = this.getThresholds();
    const daysInMonth = new Date(y, m + 1, 0).getDate();
    const offset = (new Date(y, m, 1).getDay() + 6) % 7;

    let cells = "";
    for (let i = 0; i < offset; i++) {
      cells += `<div class="ark-cal-day--empty"></div>`;
    }

    for (let d = 1; d <= daysInMonth; d++) {
      const iso = `${y}-${String(m + 1).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      const state = this.getDayState(iso, nowISO, minISO, maxISO);
      const isToday = iso === nowISO;
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
    this.renderSummary();
  },

  getDayState(iso, nowISO, minISO, maxISO) {
    // Pasado o menor a 72h
    if (iso < minISO) {
      return { css: "ark-cal-day--past", label: iso < nowISO ? "Pasado" : "&lt; 72 hrs", selectable: false };
    }
    // Superior a 365 días
    if (iso > maxISO) {
      return { css: "ark-cal-day--past", label: "+1 año", selectable: false };
    }

    // Overrides de administración (bloqueado manualmente)
    const override = AvailabilityManager.get(iso);
    if (override === "soldout") return { css: "ark-cal-day--soldout", label: "Agotado", selectable: false };
    if (override === "disabled") return { css: "ark-cal-day--disabled", label: "Bloqueado", selectable: false };

    // Capacidad: 2 eventos máximo por día
    const remaining = AvailabilityManager.remainingSlots(iso);
    if (remaining >= 2) {
      return { css: "ark-cal-day--available", label: "2 cupos", selectable: true };
    }
    if (remaining === 1) {
      return { css: "ark-cal-day--few", label: "1 cupo", selectable: true };
    }
    return { css: "ark-cal-day--soldout", label: "Agotado", selectable: false };
  },

  shiftMonth(delta) {
    this.viewDate = new Date(this.viewDate.getFullYear(), this.viewDate.getMonth() + delta, 1);
    this.render();
  },

  selectDate(iso) {
    this.selectedDate = iso;
    cart.selectedDate = iso;
    cart.persist();
    this.render();

    // Habilitar "Continuar a Ubicación & Datos" una vez que hay fecha válida
    const continueBtn = document.getElementById("btn-continue-step-2") || document.getElementById("btn-continue-step");
    if (continueBtn) {
      continueBtn.disabled = false;
      continueBtn.classList.remove("opacity-40", "pointer-events-none");
    }

    const existing = BookingStore.getBookingsForDate(iso);
    if (existing.length === 1) {
      showToast("Fecha con 1 cupo restante. Confirme la reserva del día.", "info");
    } else {
      showToast("Fecha seleccionada. Confirme la reserva del día.", "success");
    }
  },

  renderSummary() {
    const el = document.getElementById("selected-date-display") || document.getElementById("date-summary");
    if (!el) return;
    if (!this.selectedDate) {
      el.textContent = "Ninguna fecha seleccionada";
      return;
    }
    const [y, m, d] = this.selectedDate.split("-").map(Number);
    const name = CALENDAR_LOCALE.months[m - 1];
    const week = CALENDAR_LOCALE.weekdays[(new Date(y, m - 1, d).getDay() + 6) % 7];
    el.textContent = `${week} ${d} de ${name} ${y}`;
  }
};

// ============================================================
// 8. STAFF PORTAL (Login Ejecutivo FinTech + Dashboard Dual)
// ============================================================

const ADMIN_SESSION = {
  role: "",
  token: null,
  inactivityTimer: null,
  lockoutTimer: null
};

// Filtros temporales de analítica (KPIs dinámicos)
const PERIOD_FILTERS = [
  { key: "hoy", label: "Hoy" },
  { key: "semana", label: "Esta Semana" },
  { key: "mes", label: "Este Mes" },
  { key: "anio", label: "Este Año" },
  { key: "total", label: "Histórico Total" }
];

function periodRange(key) {
  const now = new Date();
  const pad = n => String(n).padStart(2, "0");
  const iso = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  if (key === "hoy") return { start: iso(now), end: iso(now) };
  if (key === "semana") {
    const dow = (now.getDay() + 6) % 7;
    const start = new Date(now);
    start.setDate(now.getDate() - dow);
    const end = new Date(start);
    end.setDate(start.getDate() + 6);
    return { start: iso(start), end: iso(end) };
  }
  if (key === "mes") {
    return {
      start: iso(new Date(now.getFullYear(), now.getMonth(), 1)),
      end: iso(new Date(now.getFullYear(), now.getMonth() + 1, 0))
    };
  }
  if (key === "anio") return { start: `${now.getFullYear()}-01-01`, end: `${now.getFullYear()}-12-31` };
  return { start: "0000-01-01", end: "9999-12-31" };
}

function bookingsInPeriod(key) {
  const { start, end } = periodRange(key);
  return BookingStore.all().filter(b => b.selectedDate && b.selectedDate >= start && b.selectedDate <= end);
}

function isNonGamLocation(province, canton) {
  if (!province) return false;
  if (!GAM_PROVINCES.includes(province)) return true;
  if (!canton) return false;
  return (NON_GAM_EXCEPTIONS[province] || []).includes(canton);
}

// ---- Auditoría del Sistema (Rol IT) ----

const AuditLog = {
  load() {
    const data = safeParse(STORAGE_KEYS.audit, null);
    if (data && typeof data === "object" && !Array.isArray(data)) return data;
    return { engineVersion: ENGINE_VERSION, logins: [], lastLogin: null };
  },

  persist(data) {
    safeSet(STORAGE_KEYS.audit, data);
  },

  recordLogin(roleId) {
    const data = this.load();
    const role = ADMIN_CONFIG.roles[roleId];
    data.logins.unshift({ role: role ? role.label : roleId, at: new Date().toISOString() });
    data.logins = data.logins.slice(0, 50);
    data.lastLogin = data.logins[0].at;
    data.engineVersion = ENGINE_VERSION;
    this.persist(data);
  },

  storageIntegrity() {
    const report = [];
    Object.entries(STORAGE_KEYS).forEach(([name, key]) => {
      try {
        const raw = localStorage.getItem(key);
        if (raw === null) {
          report.push({ name, state: "vacio" });
          return;
        }
        JSON.parse(raw);
        report.push({ name, state: "ok" });
      } catch (err) {
        report.push({ name, state: "corrupto" });
      }
    });
    return report;
  }
};

const AdminModule = {
  role: "",
  ownerFilter: "todas",
  periodFilter: "total",
  itTab: "prices",

  // ---- Apertura / Cierre (Login) ----

  open() {
    const modal = document.getElementById("adminLoginModal");
    if (!modal) return;
    trackModal(true);
    this.resetLockoutState();
    this.setRole("owner");
    this.clearAuthError();
    // Instant modal launch via deterministic ModalController
    ModalController.open("adminLoginModal");
    const pin = document.getElementById("admin-pin");
    if (pin) {
      pin.value = "";
      pin.type = "password";
      setTimeout(() => pin.focus(), 60);
    }
  },

  close() {
    const modal = document.getElementById("adminLoginModal");
    if (!modal) return;
    const pin = document.getElementById("admin-pin");
    if (pin) pin.value = "";
    // Instant modal hide via deterministic ModalController
    ModalController.close("adminLoginModal");
    this.resetLockoutState();
    clearRouteHashIfNeeded();
    trackModal(false);
  },

  openPortal() {
    const loginModal = document.getElementById("adminLoginModal");
    const portal = document.getElementById("adminPortalModal");
    if (loginModal) {
      ModalController.close("adminLoginModal");
    }
    if (!portal) return;
    ModalController.open("adminPortalModal");
    const sid = document.getElementById("admin-session-id");
    if (sid) sid.textContent = ADMIN_SESSION.token ? ADMIN_SESSION.token.replace("ARK-", "") : "—";
    this.startInactivityTimer();
    this.renderDashboard();
  },

  closePortal() {
    const portal = document.getElementById("adminPortalModal");
    if (portal) {
      ModalController.close("adminPortalModal");
    }
    this.terminateSession();
    clearRouteHashIfNeeded();
    trackModal(false);
  },

  // ---- Seguridad de Autenticación & Segmented Control ----

  setRole(roleId) {
    this.role = roleId;
    const ownerBtn = document.getElementById("admin-role-owner");
    const itBtn = document.getElementById("admin-role-it");
    if (ownerBtn) {
      const active = roleId === "owner";
      ownerBtn.classList.toggle("role-btn--active", active);
      ownerBtn.classList.toggle("text-white", active);
      ownerBtn.classList.toggle("font-semibold", active);
      ownerBtn.classList.toggle("text-gray-400", !active);
      ownerBtn.classList.toggle("font-medium", !active);
    }
    if (itBtn) {
      const active = roleId === "it";
      itBtn.classList.toggle("role-btn--active", active);
      itBtn.classList.toggle("text-white", active);
      itBtn.classList.toggle("font-semibold", active);
      itBtn.classList.toggle("text-gray-400", !active);
      itBtn.classList.toggle("font-medium", !active);
    }
    this.clearAuthError();
    const pin = document.getElementById("admin-pin");
    if (pin && !pin.disabled) {
      pin.focus();
    }
  },

  resetLockoutState() {
    if (this.lockoutTimer) {
      clearInterval(this.lockoutTimer);
      this.lockoutTimer = null;
    }
    const box = document.getElementById("admin-lockout-box");
    if (box) box.classList.add("hidden");
    this.enablePinUI(true);
    this.clearAuthError();
  },

  enablePinUI(enabled) {
    const pin = document.getElementById("admin-pin");
    if (pin) pin.disabled = !enabled;
    const submit = document.getElementById("admin-login-submit");
    if (submit) {
      submit.disabled = !enabled;
      submit.classList.toggle("opacity-50", !enabled);
      submit.classList.toggle("cursor-not-allowed", !enabled);
    }
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
    if (!this.role) {
      this.showAuthError("Seleccione un rol de acceso.");
      return;
    }
    if (!value) {
      this.showAuthError("Ingrese su PIN de acceso.");
      if (pin) pin.focus();
      return;
    }

    const result = await SecurityModule.verifyPin(this.role, value);
    if (result.ok) {
      ADMIN_SESSION.role = this.role;
      ADMIN_SESSION.token = generateBookingCode();
      AuditLog.recordLogin(this.role);
      this.ownerFilter = "todas";
      this.periodFilter = "total";
      this.openPortal();
      showToast(`Autenticado como ${ADMIN_CONFIG.roles[this.role].label}.`, "success");
      return;
    }
    if (result.locked) {
      this.startLockoutCountdown(result.waitMs);
      return;
    }
    this.showAuthError(result.remaining > 0
      ? `PIN incorrecto. Intentos restantes: ${result.remaining}.`
      : "PIN incorrecto.");
    if (pin) {
      pin.value = "";
      pin.focus();
    }
  },

  startLockoutCountdown(waitMs) {
    this.enablePinUI(false);
    this.clearAuthError();
    const box = document.getElementById("admin-lockout-box");
    const msg = document.getElementById("admin-lockout-msg");
    if (!box) return;
    box.classList.remove("hidden");
    let remaining = Math.ceil(waitMs / 1000);
    const tick = () => {
      if (msg) msg.textContent = `Bloqueo de seguridad activo. Reintente en ${remaining}s.`;
      remaining -= 1;
      if (remaining < 0) {
        clearInterval(this.lockoutTimer);
        this.lockoutTimer = null;
        box.classList.add("hidden");
        this.enablePinUI(true);
        const pin = document.getElementById("admin-pin");
        if (pin) pin.focus();
      }
    };
    tick();
    this.lockoutTimer = setInterval(tick, 1000);
  },

  // ---- Sesión: Inactividad & Liberación de Memoria ----

  startInactivityTimer() {
    this.clearInactivityTimer();
    this.inactivityTimer = setTimeout(() => {
      showToast("Sesión administrativa expirada por inactividad.", "info");
      this.terminateSession();
    }, ADMIN_CONFIG.sessionTimeoutMs || 300000);
  },

  clearInactivityTimer() {
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
      this.inactivityTimer = null;
    }
  },

  terminateSession() {
    this.clearInactivityTimer();
    this.resetLockoutState();
    ADMIN_SESSION.role = "";
    ADMIN_SESSION.token = null;
    this.role = "";
    const pin = document.getElementById("admin-pin");
    if (pin) pin.value = "";
    const loginModal = document.getElementById("adminLoginModal");
    const portal = document.getElementById("adminPortalModal");
    if (loginModal) {
      loginModal.classList.add("hidden");
      loginModal.classList.remove("flex");
    }
    if (portal) {
      portal.classList.add("hidden");
      portal.classList.remove("flex");
    }
    document.body.style.overflow = "";
  },

  logout() {
    this.terminateSession();
    this.open();
    showToast("Sesión administrativa cerrada. Memoria liberada.", "info");
  },

  // ---- Dashboard (por rol) ----

  renderDashboard() {
    const role = ADMIN_CONFIG.roles[ADMIN_SESSION.role] || ADMIN_CONFIG.roles.owner;
    const badge = document.getElementById("admin-role-badge");
    if (badge) {
      badge.textContent = `${role.label} · ${role.name}`;
      badge.className = `admin-role-badge ${ADMIN_SESSION.role === "owner" ? "admin-role-badge--owner" : "admin-role-badge--it"}`;
    }
    const ownerView = document.getElementById("admin-owner-view");
    const itView = document.getElementById("admin-it-view");
    if (ownerView) ownerView.classList.toggle("hidden", ADMIN_SESSION.role !== "owner");
    if (itView) itView.classList.toggle("hidden", ADMIN_SESSION.role !== "it");
    if (ADMIN_SESSION.role === "owner") this.renderOwner();
    else this.renderIT();
  },

  // ---- Rol Propietario: Analítica Financiera ----

  renderOwner() {
    this.renderOwnerPeriodFilters();
    this.renderOwnerMetrics();
    this.renderOwnerSparkline();
    this.renderOwnerFilters();
    this.renderOwnerBookings();
  },

  renderOwnerPeriodFilters() {
    const box = document.getElementById("portal-period-filters");
    if (!box) return;
    box.innerHTML = PERIOD_FILTERS.map(f => {
      const active = f.key === this.periodFilter ? "admin-tab-btn--active" : "";
      return `<button type="button" data-period="${f.key}" class="admin-tab-btn ${active}">${f.label}</button>`;
    }).join("");
  },

  renderOwnerMetrics() {
    const list = bookingsInPeriod(this.periodFilter);
    const active = list.filter(b => b.status !== "cancelada");
    const validatedDeposits = active
      .filter(b => b.status === "confirmada" || b.status === "realizada")
      .reduce((s, b) => s + b.deposit50Amount, 0);
    const receivable = active.reduce((s, b) => s + b.remainingBalance, 0);
    const projected = active.reduce((s, b) => s + b.granTotal, 0);

    let spanDays = Math.max(1, Math.round((parseISO(periodRange(this.periodFilter).end) - parseISO(periodRange(this.periodFilter).start)) / 86400000) + 1);
    if (this.periodFilter === "total") {
      const dates = active.map(b => parseISO(b.selectedDate)).filter(Boolean).sort((a, b) => a - b);
      spanDays = dates.length >= 2 ? Math.max(1, Math.round((dates[dates.length - 1] - dates[0]) / 86400000) + 1) : 1;
    }
    const capacity = spanDays * DEFAULT_MAX_EVENTS_PER_DAY;
    const occupancy = Math.min(100, Math.round((active.length / capacity) * 100));

    const box = document.getElementById("admin-metrics");
    if (!box) return;
    box.innerHTML = [
      kpiCard("💳", "Adelantos SINPE Validados (50%)", formatCRC(validatedDeposits), "border-emerald-500/40"),
      kpiCard("🤝", "Saldos por Cobrar en Escenario", formatCRC(receivable), "border-pink-500/40"),
      kpiCard("📊", "Facturación Proyectada Total", formatCRC(projected), "border-cyan-500/40"),
      kpiCard("📅", "Eventos Activos & Ocupación", `${active.length} activos · ${occupancy}% ocupación`, "border-purple-500/40")
    ].join("");
  },

  renderOwnerSparkline() {
    const box = document.getElementById("portal-sparkline");
    if (!box) return;
    const list = bookingsInPeriod(this.periodFilter).filter(b => b.status !== "cancelada");
    const byDate = {};
    list.forEach(b => {
      if (!byDate[b.selectedDate]) byDate[b.selectedDate] = { validated: 0, receivable: 0 };
      const rec = byDate[b.selectedDate];
      if (b.status === "confirmada" || b.status === "realizada") {
        rec.validated += b.deposit50Amount;
        rec.receivable += b.remainingBalance;
      } else {
        rec.receivable += b.granTotal;
      }
    });
    const dates = Object.keys(byDate).sort();
    if (!dates.length) {
      box.innerHTML = `<div class="p-6 rounded-2xl bg-white/5 border border-white/10 text-center"><p class="text-xs text-gray-500">Sin flujo de caja en el período seleccionado.</p></div>`;
      return;
    }
    const data = dates.map(d => ({ date: d, ...byDate[d] }));
    const maxVal = Math.max(...data.map(x => x.validated + x.receivable), 1);
    const W = 640, H = 200, padB = 26, padT = 12;
    const chartH = H - padB - padT;
    const step = data.length > 1 ? (W - 24) / (data.length - 1) : W - 24;
    const barW = Math.min(26, Math.max(6, step * 0.55));

    const bars = data.map((x, i) => {
      const cx = 12 + i * step;
      const vH = (x.validated / maxVal) * chartH;
      const rH = (x.receivable / maxVal) * chartH;
      const vY = padT + chartH - vH;
      const rY = vY - rH;
      const title = `${x.date} — Validado: ${formatCRC(x.validated)} · Por cobrar: ${formatCRC(x.receivable)}`;
      return `
      <g>
        <rect x="${(cx - barW / 2).toFixed(2)}" y="${rY.toFixed(2)}" width="${barW.toFixed(2)}" height="${Math.max(1, rH).toFixed(2)}" rx="3" fill="rgba(236,72,153,0.75)">
          <title>${title}</title>
        </rect>
        <rect x="${(cx - barW / 2).toFixed(2)}" y="${vY.toFixed(2)}" width="${barW.toFixed(2)}" height="${Math.max(1, vH).toFixed(2)}" rx="3" fill="rgba(16,185,129,0.9)">
          <title>${title}</title>
        </rect>
        <text x="${cx.toFixed(2)}" y="${H - 8}" text-anchor="middle" font-size="9" fill="#94a3b8">${x.date.slice(5)}</text>
      </g>`;
    }).join("");

    box.innerHTML = `
      <div class="p-5 rounded-2xl bg-white/5 border border-purple-500/20">
        <div class="flex flex-wrap items-center justify-between gap-2 mb-3">
          <p class="text-xs font-bold text-gray-300 uppercase tracking-wider">Flujo de Caja por Fecha de Evento</p>
          <div class="flex items-center gap-4 text-[10px] font-semibold">
            <span class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-sm bg-emerald-400 inline-block"></span> Efectivo Validado (50%)</span>
            <span class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-sm bg-pink-400 inline-block"></span> Saldo por Cobrar</span>
          </div>
        </div>
        <svg viewBox="0 0 ${W} ${H}" class="w-full h-auto" role="img" aria-label="Gráfico de flujo de caja por fecha">
          <line x1="12" y1="${padT}" x2="12" y2="${H - padB}" stroke="rgba(168,85,247,0.2)" stroke-width="1"/>
          <line x1="12" y1="${H - padB}" x2="${W - 12}" y2="${H - padB}" stroke="rgba(168,85,247,0.2)" stroke-width="1"/>
          ${bars}
        </svg>
      </div>`;
  },

  renderOwnerFilters() {
    const box = document.getElementById("admin-status-filters");
    if (!box) return;
    const statuses = [
      ["todas", "Todas"],
      ["pendiente", "Pendientes de Aprobación"],
      ["confirmada", "Confirmadas"],
      ["realizada", "Realizadas"],
      ["cancelada", "Canceladas"]
    ];
    const periodList = bookingsInPeriod(this.periodFilter);
    box.innerHTML = statuses.map(([key, label]) => {
      const count = key === "todas" ? periodList.length : periodList.filter(b => b.status === key).length;
      const active = key === this.ownerFilter ? "admin-tab-btn--active" : "";
      return `<button type="button" data-filter="${key}" class="admin-tab-btn ${active}">${label} (${count})</button>`;
    }).join("");
  },

  renderOwnerBookings() {
    const box = document.getElementById("admin-bookings-list");
    if (!box) return;
    const periodList = bookingsInPeriod(this.periodFilter);
    const list = periodList.filter(b => this.ownerFilter === "todas" || b.status === this.ownerFilter);
    if (!list.length) {
      box.innerHTML = `<div class="p-8 rounded-2xl bg-white/5 border border-white/10 text-center"><p class="text-xs text-gray-500">No hay reservas registradas en esta categoría.</p></div>`;
      return;
    }
    box.innerHTML = list.map(bookingCard).join("");
  },

  // ---- Rol Ingeniero de TI: Suite de Control Técnico (4 Pestañas Modulares) ----

  renderIT() {
    const tabs = ["prices", "gallery", "availability", "backup"];
    tabs.forEach(p => {
      const el = document.getElementById(`admin-it-${p}`);
      if (el) el.classList.toggle("hidden", p !== this.itTab);
    });
    document.querySelectorAll("[data-it-tab]").forEach(t => {
      t.classList.toggle("admin-tab-btn--active", t.getAttribute("data-it-tab") === this.itTab);
    });
    const pricesEl = document.getElementById("admin-it-prices");
    const galleryEl = document.getElementById("admin-it-gallery");
    const availEl = document.getElementById("admin-it-availability");
    const backupEl = document.getElementById("admin-it-backup");
    if (pricesEl && this.itTab === "prices") pricesEl.innerHTML = this.itPricesHtml();
    if (galleryEl && this.itTab === "gallery") galleryEl.innerHTML = this.itGalleryHtml();
    if (availEl && this.itTab === "availability") availEl.innerHTML = this.itAvailabilityHtml();
    if (backupEl && this.itTab === "backup") backupEl.innerHTML = this.itBackupHtml();
  },

  setItTab(tab) {
    this.itTab = tab;
    this.renderIT();
  },

  itPricesHtml() {
    const extraMultiplier = StorageEngine.getConfig("extraHourMultiplier", 0.50);
    const travelRate = StorageEngine.getConfig("travelSurchargeRate", NON_GAM_SURCHARGE_RATE);
    const djPrice = PriceManager.getExtraPrice("dj_service") || DYNAMIC_EXTRAS_CONFIG.dj_service.unitPrice;
    const subPrice = PriceManager.getExtraPrice("subwoofers") || DYNAMIC_EXTRAS_CONFIG.subwoofers.unitPrice;

    const serviceRows = CATALOG_SERVICES.map(s => `
      <tr class="border-b border-white/5">
        <td class="py-2.5 pr-2">
          <p class="text-sm font-bold text-white">${sanitizeInput(s.name)}</p>
          <p class="text-[10px] text-gray-500">Montaje ${s.setup_display || "2h antes"} · Desmontaje ${s.teardown_display || "1h después"}</p>
        </td>
        <td class="py-2.5 px-2 text-right text-xs text-gray-400 whitespace-nowrap">${formatCRC(s.price_crc)}</td>
        <td class="py-2.5 pl-2">
          <div class="flex items-center gap-1.5 justify-end">
            <span class="text-xs text-gray-400 font-bold">₡</span>
            <input type="number" data-price="service-${s.id}" value="${PriceManager.getServicePrice(s)}"
              min="0" step="5000" class="glass-input rounded-xl px-3 py-2 w-32 sm:w-36 text-sm font-bold">
          </div>
        </td>
      </tr>`).join("");

    return `
      <div class="p-5 rounded-2xl bg-white/5 border border-purple-500/25 overflow-x-auto space-y-6">
        <div>
          <p class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-3">Matriz de Tarifas Base en Vivo (6 Formatos)</p>
          <table class="w-full min-w-[520px] text-xs">
            <thead>
              <tr class="text-left text-[10px] uppercase tracking-wider text-gray-500 border-b border-white/10">
                <th class="py-2 pr-2">Formato / Servicio</th>
                <th class="py-2 px-2 text-right">Tarifa Catálogo</th>
                <th class="py-2 pl-2 text-right">Tarifa Vigente (Tiempo Real)</th>
              </tr>
            </thead>
            <tbody>
              ${serviceRows}
            </tbody>
          </table>
        </div>

        <div class="border-t border-white/10 pt-5">
          <p class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-3">Parámetros Dinámicos de Extras & Viáticos</p>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="p-3.5 rounded-xl bg-black/30 border border-white/5 space-y-1.5">
              <label class="block text-[11px] font-bold text-purple-300" for="admin-extra-multiplier">Multiplicador Hora Extra</label>
              <div class="flex items-center gap-1.5">
                <input type="number" id="admin-extra-multiplier" value="${extraMultiplier}" min="0.1" max="2.0" step="0.05"
                  class="glass-input rounded-xl px-3 py-2 w-full text-sm font-bold text-white">
                <span class="text-xs text-gray-400 font-bold">(${(extraMultiplier * 100).toFixed(0)}%)</span>
              </div>
              <p class="text-[10px] text-gray-500">Por defecto: 0.50 (50% de la tarifa base)</p>
            </div>

            <div class="p-3.5 rounded-xl bg-black/30 border border-white/5 space-y-1.5">
              <label class="block text-[11px] font-bold text-pink-300" for="admin-travel-rate">Recargo Fuera de GAM (%)</label>
              <div class="flex items-center gap-1.5">
                <input type="number" id="admin-travel-rate" value="${(travelRate * 100).toFixed(0)}" min="0" max="100" step="1"
                  class="glass-input rounded-xl px-3 py-2 w-full text-sm font-bold text-white">
                <span class="text-xs text-gray-400 font-bold">%</span>
              </div>
              <p class="text-[10px] text-gray-500">Por defecto: 12% viáticos de transporte</p>
            </div>

            <div class="p-3.5 rounded-xl bg-black/30 border border-white/5 space-y-1.5">
              <label class="block text-[11px] font-bold text-cyan-300" for="admin-subwoofer-price">Subwoofer Extra (Unidad)</label>
              <div class="flex items-center gap-1.5">
                <span class="text-xs text-gray-400 font-bold">₡</span>
                <input type="number" id="admin-subwoofer-price" data-price="extra-subwoofers" value="${subPrice}" min="0" step="5000"
                  class="glass-input rounded-xl px-3 py-2 w-full text-sm font-bold text-white">
              </div>
              <p class="text-[10px] text-gray-500">Original: ₡80,000 / unidad</p>
            </div>

            <div class="p-3.5 rounded-xl bg-black/30 border border-white/5 space-y-1.5">
              <label class="block text-[11px] font-bold text-emerald-300" for="admin-dj-price">Servicio DJ Recesos (Hora)</label>
              <div class="flex items-center gap-1.5">
                <span class="text-xs text-gray-400 font-bold">₡</span>
                <input type="number" id="admin-dj-price" data-price="extra-dj_service" value="${djPrice}" min="0" step="5000"
                  class="glass-input rounded-xl px-3 py-2 w-full text-sm font-bold text-white">
              </div>
              <p class="text-[10px] text-gray-500">Original: ₡75,000 / hora</p>
            </div>
          </div>
        </div>

        <div class="flex flex-wrap gap-3 pt-2">
          <button type="button" id="admin-save-prices" class="admin-act-btn admin-act-btn--confirm">💾 Guardar y Aplicar Precios</button>
          <button type="button" id="admin-reset-prices" class="admin-act-btn admin-act-btn--neutral">↺ Restaurar Precios de Fábrica</button>
        </div>
      </div>`;
  },

  itGalleryHtml() {
    const items = StorageEngine.getGalleryItems();
    const featuredCount = items.filter(i => i.featured).length;

    const rows = items.map(item => `
      <div class="admin-media-row flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-2xl bg-white/5 border border-white/10" data-media-id="${item.id}">
        <div class="flex items-center gap-3 min-w-0">
          <div class="w-12 h-12 rounded-xl overflow-hidden bg-black/50 flex-shrink-0 border border-white/15">
            <img src="${sanitizeUrl(item.thumbnail)}" alt="${sanitizeInput(item.title)}" class="w-full h-full object-cover">
          </div>
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <p class="text-sm font-bold text-white truncate">${sanitizeInput(item.title)}</p>
              ${item.featured ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-pink-500/20 text-pink-300 border border-pink-500/40">⭐ Destacado</span>' : ''}
            </div>
            <div class="flex items-center gap-2 text-[11px] text-gray-400 mt-0.5">
              <span class="px-2 py-0.5 rounded-md bg-purple-950/60 text-purple-300 font-semibold uppercase text-[10px]">${sanitizeInput(GALLERY_CATEGORY_LABELS[item.category] || item.category)}</span>
              <span>·</span>
              <span class="uppercase text-[10px] text-gray-500 font-bold">${sanitizeInput(item.type)}</span>
              <span>·</span>
              <span class="text-gray-400">${sanitizeInput(item.date || "")}</span>
            </div>
          </div>
        </div>

        <div class="flex items-center gap-1.5 flex-wrap">
          <button type="button" onclick="AdminModule.toggleFeaturedMedia('${item.id}')"
            class="admin-act-btn ${item.featured ? 'admin-act-btn--confirm' : 'admin-act-btn--neutral'} text-xs py-1.5 px-3 min-h-[38px]"
            title="Alternar estado destacado">
            ${item.featured ? '★ Quitar Destacado' : '☆ Destacar'}
          </button>
          <button type="button" onclick="AdminModule.openMediaModal('${item.id}')"
            class="admin-act-btn admin-act-btn--neutral text-xs py-1.5 px-3 min-h-[38px]">
            ✏️ Editar
          </button>
          <button type="button" onclick="AdminModule.deleteMediaItem('${item.id}')"
            class="admin-act-btn admin-act-btn--cancel text-xs py-1.5 px-3 min-h-[38px]">
            🗑️ Eliminar
          </button>
        </div>
      </div>
    `).join("");

    return `
      <div class="p-5 rounded-2xl bg-white/5 border border-purple-500/25 space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p class="text-xs font-bold text-gray-300 uppercase tracking-wider">Gestor Dinámico de Galería & Social Showcase</p>
            <p class="text-[11px] text-gray-400">Total: <strong>${items.length}</strong> elementos registrados · <strong>${featuredCount}</strong> destacados</p>
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <button type="button" onclick="AdminModule.openMediaModal()"
              class="admin-act-btn admin-act-btn--confirm flex items-center gap-1.5 text-xs py-2 px-4 shadow-lg">
              <span>➕ Añadir Nuevo Contenido</span>
            </button>
            <button type="button" onclick="AdminModule.resetMediaItems()"
              class="admin-act-btn admin-act-btn--neutral text-xs py-2 px-3">
              ↺ Restaurar Inicial
            </button>
          </div>
        </div>

        <div class="space-y-2.5 max-h-[550px] overflow-y-auto pr-1">
          ${rows.length ? rows : '<p class="text-xs text-gray-500 text-center py-6">No hay elementos en la galería. Añada uno nuevo con el botón superior.</p>'}
        </div>
      </div>
    `;
  },

  itAvailabilityHtml() {
    const todayISO = isoOf(new Date());
    const overrides = AvailabilityManager.all();
    const entries = Object.keys(overrides).sort();
    return `
      <div class="p-5 rounded-2xl bg-white/5 border border-purple-500/25 space-y-5">
        <div>
          <p class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">Bloqueo de Fechas (Mantenimiento · Cierre Privado · Descanso)</p>
          <div class="flex flex-wrap items-end gap-2">
            <input type="date" id="admin-avail-date" min="${todayISO}" class="glass-input rounded-xl px-3 py-2.5 text-sm">
            <button type="button" data-avail="disabled" class="admin-act-btn admin-act-btn--cancel">⛔ Bloquear Fecha</button>
            <button type="button" data-avail="available" class="admin-act-btn admin-act-btn--confirm">🟢 Desbloquear Fecha</button>
            <button type="button" data-avail="soldout" class="admin-act-btn admin-act-btn--neutral">🔴 Marcar Agotado (2 eventos)</button>
          </div>
        </div>
        <div>
          <p class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">Fechas con Gestión Manual (${entries.length})</p>
          <div class="space-y-2">
            ${entries.length ? entries.map(k => `
              <div class="flex items-center justify-between gap-3 p-3 rounded-xl bg-white/5 border border-white/10">
                <span class="text-sm font-bold text-white">${k}</span>
                <span class="status-badge ${overrides[k] === "soldout" ? "status-badge--soldout" : "status-badge--disabled"}">
                  ${overrides[k] === "soldout" ? "Agotado" : "Bloqueado"}
                </span>
                <button type="button" data-avail-remove="${k}" class="text-xs text-red-400 hover:text-red-300 font-semibold">Quitar Bloqueo</button>
              </div>`).join("")
        : `<p class="text-xs text-gray-500">Sin bloqueos manuales. Disponibilidad calculada automáticamente (máx. 2 eventos/día · antelación mínima 72 h).</p>`}
          </div>
        </div>
      </div>`;
  },

  itBackupHtml() {
    const audit = AuditLog.load();
    const integrity = AuditLog.storageIntegrity();
    const lastLogin = audit.lastLogin ? new Date(audit.lastLogin).toLocaleString("es-CR") : "Nunca";
    const storageStats = StorageEngine.getStorageStats();

    const integrityRows = integrity.map(i => `
      <div class="flex items-center justify-between gap-3 p-2.5 rounded-lg bg-white/5 border border-white/10">
        <span class="text-xs font-bold text-gray-200 font-mono">${i.name}</span>
        <span class="text-[10px] font-bold px-2 py-0.5 rounded-full ${i.state === "ok" ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/40" : (i.state === "corrupto" ? "bg-red-500/15 text-red-300 border border-red-500/40" : "bg-gray-500/15 text-gray-400 border border-gray-500/30")}">
          ${i.state === "ok" ? "Integridad OK" : (i.state === "corrupto" ? "Corrupto" : "Vacío")}
        </span>
      </div>`).join("");

    return `
      <div class="space-y-5">
        <div class="p-5 rounded-2xl bg-white/5 border border-purple-500/25 space-y-4">
          <p class="text-sm font-bold text-white">Database Vault — Respaldo & Restauración Total</p>
          <p class="text-xs text-gray-400 leading-relaxed">Exporte la base de datos completa (reservas, tarifas en vivo, agenda de bloqueos, biblioteca multimedia y configuración) en un archivo JSON validable.</p>
          <div class="flex flex-wrap gap-3">
            <button type="button" id="admin-export-backup" class="admin-act-btn admin-act-btn--confirm">⬇ Exportar Base de Datos (JSON)</button>
            <label class="admin-act-btn admin-act-btn--neutral cursor-pointer">
              ⬆ Importar / Restaurar Respaldo (JSON)
              <input type="file" id="admin-import-backup" accept=".json,application/json" class="hidden">
            </label>
          </div>
          <p id="admin-backup-status" class="text-[11px] text-purple-300 pt-1">
            📊 ${BookingStore.all().length} reservas registradas · ${Object.keys(AvailabilityManager.all()).length} fechas bloqueadas · ${StorageEngine.getGalleryItems().length} medios en galería
          </p>
        </div>

        <div class="p-5 rounded-2xl bg-white/5 border border-purple-500/25 space-y-4">
          <div class="flex items-center justify-between">
            <p class="text-xs font-bold text-gray-300 uppercase tracking-wider">Telemetría de Almacenamiento & Seguridad</p>
            <span class="text-xs font-mono text-emerald-400 font-bold">Uso LocalStorage: ${storageStats.totalKb} KB</span>
          </div>

          <!-- Storage Meter Bar -->
          <div class="w-full bg-black/40 h-2.5 rounded-full overflow-hidden border border-white/10">
            <div class="storage-meter-fill h-full rounded-full" style="width: ${Math.min(100, Math.max(5, (storageStats.totalBytes / (5 * 1024 * 1024)) * 100 * 50))}%"></div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div class="p-3 rounded-xl bg-black/30 border border-white/5">
              <p class="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Versión del Motor</p>
              <p class="text-sm font-extrabold text-purple-300 mt-1 font-mono">${ENGINE_VERSION}</p>
            </div>
            <div class="p-3 rounded-xl bg-black/30 border border-white/5">
              <p class="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Último Acceso IT</p>
              <p class="text-sm font-extrabold text-white mt-1">${lastLogin}</p>
            </div>
            <div class="p-3 rounded-xl bg-black/30 border border-white/5">
              <p class="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Criptografía SHA-256</p>
              <p class="text-sm font-extrabold text-emerald-400 mt-1">${window.crypto && window.crypto.subtle ? "Hardware Activo" : "FNV-1a Fallback"}</p>
            </div>
          </div>

          <div class="space-y-2 pt-2">${integrityRows}</div>

          ${audit.logins.length ? `
          <div class="mt-4 pt-3 border-t border-white/10">
            <p class="text-[10px] uppercase tracking-wider text-gray-500 font-bold mb-2">Historial de Ingresos de Seguridad</p>
            <div class="space-y-1.5 max-h-36 overflow-y-auto pr-1">
              ${audit.logins.slice(0, 10).map(l => `
                <div class="flex items-center justify-between text-[11px] py-1 border-b border-white/5">
                  <span class="text-gray-300 font-semibold">${sanitizeInput(l.role)}</span>
                  <span class="text-gray-500 font-mono">${new Date(l.at).toLocaleString("es-CR")}</span>
                </div>`).join("")}
            </div>
          </div>` : ""}
        </div>
      </div>`;
  },

  // ---- Métodos CRUD para el Gestor de Galería (Rol IT) ----

  openMediaModal(id) {
    const modal = document.getElementById("adminMediaModal");
    if (!modal) return;
    const idInput = document.getElementById("admin-media-id");
    const titleInput = document.getElementById("admin-media-title");
    const catInput = document.getElementById("admin-media-category");
    const typeInput = document.getElementById("admin-media-type");
    const thumbInput = document.getElementById("admin-media-thumbnail");
    const embedInput = document.getElementById("admin-media-embed");
    const directInput = document.getElementById("admin-media-direct");
    const dateInput = document.getElementById("admin-media-date");
    const featInput = document.getElementById("admin-media-featured");
    const captionInput = document.getElementById("admin-media-caption");
    const modalTitle = document.getElementById("admin-media-modal-title");

    if (id) {
      const item = StorageEngine.getGalleryItems().find(m => String(m.id) === String(id));
      if (item) {
        if (idInput) idInput.value = item.id;
        if (titleInput) titleInput.value = item.title || "";
        if (catInput) catInput.value = item.category || "instagram";
        if (typeInput) typeInput.value = item.type || "instagram";
        if (thumbInput) thumbInput.value = item.thumbnail || "";
        if (embedInput) embedInput.value = item.embedUrl || "";
        if (directInput) directInput.value = item.directUrl || item.url || "";
        if (dateInput) dateInput.value = item.date || "";
        if (featInput) featInput.checked = Boolean(item.featured);
        if (captionInput) captionInput.value = item.caption || item.subtitle || "";
        if (modalTitle) modalTitle.textContent = "Editar Contenido";
      }
    } else {
      if (idInput) idInput.value = "";
      if (titleInput) titleInput.value = "";
      if (catInput) catInput.value = "instagram";
      if (typeInput) typeInput.value = "instagram";
      if (thumbInput) thumbInput.value = "";
      if (embedInput) embedInput.value = "";
      if (directInput) directInput.value = "https://www.instagram.com/kikeramirezcr";
      if (dateInput) dateInput.value = "Agosto 2026";
      if (featInput) featInput.checked = false;
      if (captionInput) captionInput.value = "";
      if (modalTitle) modalTitle.textContent = "Añadir Nuevo Contenido";
    }

    modal.classList.remove("hidden");
    modal.classList.add("flex");
  },

  closeMediaModal() {
    const modal = document.getElementById("adminMediaModal");
    if (modal) {
      modal.classList.add("hidden");
      modal.classList.remove("flex");
    }
  },

  saveMediaItem() {
    const idInput = document.getElementById("admin-media-id");
    const titleInput = document.getElementById("admin-media-title");
    const catInput = document.getElementById("admin-media-category");
    const typeInput = document.getElementById("admin-media-type");
    const thumbInput = document.getElementById("admin-media-thumbnail");
    const embedInput = document.getElementById("admin-media-embed");
    const directInput = document.getElementById("admin-media-direct");
    const dateInput = document.getElementById("admin-media-date");
    const featInput = document.getElementById("admin-media-featured");
    const captionInput = document.getElementById("admin-media-caption");

    const title = titleInput ? titleInput.value.trim() : "";
    const thumbnail = thumbInput ? thumbInput.value.trim() : "";

    if (!title || !thumbnail) {
      showToast("Título y URL de miniatura son obligatorios.", "error");
      return;
    }

    const payload = {
      title: sanitizeInput(title),
      category: catInput ? catInput.value : "instagram",
      type: typeInput ? typeInput.value : "instagram",
      thumbnail: sanitizeUrl(thumbnail),
      embedUrl: embedInput ? sanitizeUrl(embedInput.value.trim()) : "",
      directUrl: directInput ? sanitizeUrl(directInput.value.trim()) : "https://www.instagram.com/kikeramirezcr",
      url: directInput ? sanitizeUrl(directInput.value.trim()) : "https://www.instagram.com/kikeramirezcr",
      date: dateInput ? sanitizeInput(dateInput.value.trim()) : "2026",
      featured: featInput ? featInput.checked : false,
      caption: captionInput ? sanitizeInput(captionInput.value.trim()) : "",
      subtitle: captionInput ? sanitizeInput(captionInput.value.trim()) : ""
    };

    const editId = idInput ? idInput.value : "";
    if (editId) {
      StorageEngine.updateGalleryItem(editId, payload);
      showToast("Elemento actualizado correctamente.", "success");
    } else {
      StorageEngine.addGalleryItem(payload);
      showToast("Nuevo elemento añadido a la galería.", "success");
    }

    this.closeMediaModal();
    this.renderIT();
  },

  deleteMediaItem(id) {
    if (confirm("¿Está seguro de eliminar este elemento de la galería?")) {
      StorageEngine.deleteGalleryItem(id);
      showToast("Elemento eliminado de la galería.", "success");
      this.renderIT();
    }
  },

  toggleFeaturedMedia(id) {
    StorageEngine.toggleFeaturedGalleryItem(id);
    showToast("Estado destacado actualizado.", "success");
    this.renderIT();
  },

  resetMediaItems() {
    if (confirm("¿Restaurar la galería de contenido original por defecto?")) {
      StorageEngine.resetGalleryItems();
      showToast("Galería restaurada a valores por defecto.", "success");
      this.renderIT();
    }
  }
};

function kpiCard(icon, label, value, border) {
  return `
    <div class="p-4 rounded-2xl bg-white/5 border ${border} backdrop-blur-md gpu">
      <p class="text-[10px] font-bold uppercase tracking-wider text-gray-400 flex items-center gap-1.5"><span class="text-sm">${icon}</span> ${label}</p>
      <p class="text-lg font-extrabold text-white mt-2 break-all">${value}</p>
    </div>`;
}

function bookingCard(b) {
  const statusLabel = BOOKING_STATUSES[b.status] || b.status;
  const service = CATALOG_SERVICES.find(s => s.id === b.serviceId);
  const setupDisplay = service ? service.setup_display : (b.setupDisplay || "2h antes");
  const teardownDisplay = service ? service.teardown_display : (b.teardownDisplay || "1h después");
  const gam = isNonGamLocation(b.province, b.canton);
  const gamBadge = gam
    ? `<span class="px-2 py-0.5 rounded-md bg-amber-500/10 border border-amber-500/40 text-amber-300 text-[10px] font-bold">🚚 Fuera GAM · +12% (${formatCRC(b.travelSurcharge || 0)})</span>`
    : `<span class="px-2 py-0.5 rounded-md bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 text-[10px] font-bold">📍 GAM · Viáticos ₡0</span>`;

  const actions = [];
  if (b.status === "pendiente") {
    actions.push(`<button type="button" data-action="confirm" class="admin-act-btn admin-act-btn--confirm">💳 Validar Pago Bancario</button>`);
  }
  if (b.status === "confirmada") {
    actions.push(`<button type="button" data-action="complete" class="admin-act-btn admin-act-btn--confirm">✅ Marcar Realizada</button>`);
  }
  if (b.status === "pendiente" || b.status === "confirmada") {
    actions.push(`<button type="button" data-action="cancel" class="admin-act-btn admin-act-btn--cancel">✕ Rechazar / Cancelar</button>`);
  }
  if (b.status !== "cancelada" && b.status !== "pendiente") {
    actions.push(`<button type="button" data-action="voucher" class="admin-act-btn admin-act-btn--neutral">📄 Descargar Voucher PDF</button>`);
  }
  actions.push(`<button type="button" data-action="whatsapp" class="admin-act-btn admin-act-btn--whatsapp">💬 Notificar WhatsApp</button>`);

  return `
  <div class="admin-booking-row rounded-2xl border border-purple-500/20 bg-white/5 p-5" data-id="${b.code}">
    <div class="flex flex-wrap items-center justify-between gap-2 mb-3">
      <div class="flex items-center gap-2 flex-wrap">
        <span class="font-mono font-extrabold text-purple-300 text-sm">${b.code}</span>
        <span class="status-badge status-badge--${b.status}">${statusLabel}</span>
        ${gamBadge}
      </div>
      <span class="text-xs text-gray-400">📅 ${b.selectedDate}</span>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-5 gap-y-2 text-xs text-gray-300">
      <p><span class="text-gray-500 block text-[10px] uppercase tracking-wider">Cliente / Empresa</span><strong class="text-white">${sanitizeInput(b.clientName)}</strong></p>
      <p><span class="text-gray-500 block text-[10px] uppercase tracking-wider">Formato Musical</span>${sanitizeInput(b.serviceName)} · ${sanitizeInput(b.eventType || "")}</p>
      <p><span class="text-gray-500 block text-[10px] uppercase tracking-wider">Contacto</span>${sanitizeInput(b.clientPhone)} · ${sanitizeInput(b.clientEmail || "")}</p>
      <p><span class="text-gray-500 block text-[10px] uppercase tracking-wider">Logística</span>Montaje ${setupDisplay} · Desmontaje ${teardownDisplay}</p>
      <p><span class="text-gray-500 block text-[10px] uppercase tracking-wider">Ubicación</span>${sanitizeInput(b.canton)}, ${sanitizeInput(b.province)}</p>
      <p><span class="text-gray-500 block text-[10px] uppercase tracking-wider">Ref. SINPE</span><span class="font-mono font-bold text-cyan-300">${b.sinpeRef ? sanitizeInput(b.sinpeRef) : "S/N"}</span></p>
    </div>

    <div class="mt-3 p-3 rounded-xl bg-black/30 border border-white/5 grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
      <div class="flex justify-between sm:block">
        <span class="text-gray-500 block text-[10px] uppercase tracking-wider">Gran Total</span>
        <span class="font-bold text-white">${formatCRC(b.granTotal)}</span>
      </div>
      <div class="flex justify-between sm:block">
        <span class="text-gray-500 block text-[10px] uppercase tracking-wider">Adelanto SINPE (50%)</span>
        <span class="font-bold text-emerald-400">${formatCRC(b.deposit50Amount)}</span>
      </div>
      <div class="flex justify-between sm:block">
        <span class="text-gray-500 block text-[10px] uppercase tracking-wider">Saldo en Evento</span>
        <span class="font-bold text-pink-400">${formatCRC(b.remainingBalance)}</span>
      </div>
    </div>

    <div class="flex flex-wrap gap-2 mt-4 pt-3 border-t border-white/5">
      ${actions.join("")}
    </div>
  </div>`;
}

function whatsappClientUrl(booking, message) {
  return `https://wa.me/${normalizeWaPhone(booking.clientPhone)}?text=${encodeURIComponent(message)}`;
}

// ============================================================
// 9. PDF EXPORT ENGINE (Voucher de Cliente & Reporte Ejecutivo de Propietario)
// ============================================================

/**
 * Construye el HTML del voucher oficial de reserva (formato imprimible/PDF).
 */
function buildVoucherHtml(b) {
  const service = CATALOG_SERVICES.find(s => s.id === b.serviceId);

  const container = document.createElement("div");
  container.style.padding = "24px";
  container.style.fontFamily = "'Helvetica Neue', Helvetica, Arial, sans-serif";
  container.style.color = "#111827";
  container.style.background = "#ffffff";
  container.style.maxWidth = "750px";
  container.style.margin = "0 auto";

  container.innerHTML = `
    <div style="border-bottom: 2px solid #8b5cf6; padding-bottom: 16px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center;">
      <div>
        <h1 style="margin: 0; font-size: 24px; color: #6d28d9; font-weight: 800;">ARKIK PRODUCTIONS</h1>
        <p style="margin: 3px 0 0 0; font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 1px;">Música en Vivo & Sonido Profesional · Costa Rica</p>
        <p style="margin: 2px 0 0 0; font-size: 11px; color: #4b5563;">Sede: Granadilla, San José · Tel: +506 6227-4984</p>
      </div>
      <div style="text-align: right;">
        <span style="display: inline-block; background: #f3e8ff; color: #7c3aed; border: 1px solid #c084fc; padding: 6px 12px; border-radius: 8px; font-size: 14px; font-weight: 800; font-family: monospace;">${b.code}</span>
        <p style="margin: 4px 0 0 0; font-size: 10px; color: #9ca3af;">Fecha emisión: ${new Date().toLocaleDateString("es-CR")}</p>
      </div>
    </div>

    <div style="background: #faf5ff; border: 1px solid #e9d5ff; border-radius: 10px; padding: 14px; margin-bottom: 18px;">
      <h3 style="margin: 0 0 8px 0; font-size: 13px; color: #6b21a8; text-transform: uppercase; letter-spacing: 0.5px;">Estado de Reserva: <strong>${BOOKING_STATUSES[b.status] || "Pendiente de Aprobación"}</strong></h3>
      <p style="margin: 0; font-size: 11px; color: #4c1d95; line-height: 1.4;">
        ${SINPE_CONFIG.policyText}
      </p>
    </div>

    <table style="width: 100%; border-collapse: collapse; margin-bottom: 18px; font-size: 12px;">
      <tr>
        <td style="padding: 6px 0; color: #6b7280; width: 35%;">Cliente / Empresa:</td>
        <td style="padding: 6px 0; font-weight: 700; color: #111827;">${sanitizeInput(b.clientName)}</td>
      </tr>
      <tr>
        <td style="padding: 6px 0; color: #6b7280;">Teléfono (WhatsApp):</td>
        <td style="padding: 6px 0; font-weight: 600; color: #111827;">${sanitizeInput(b.clientPhone)}</td>
      </tr>
      <tr>
        <td style="padding: 6px 0; color: #6b7280;">Correo Electrónico:</td>
        <td style="padding: 6px 0; font-weight: 600; color: #111827;">${sanitizeInput(b.clientEmail || "No especificado")}</td>
      </tr>
      <tr>
        <td style="padding: 6px 0; color: #6b7280;">Tipo de Evento:</td>
        <td style="padding: 6px 0; font-weight: 700; color: #111827;">${sanitizeInput(b.eventType)}</td>
      </tr>
      <tr>
        <td style="padding: 6px 0; color: #6b7280;">Fecha del Show:</td>
        <td style="padding: 6px 0; font-weight: 800; color: #7c3aed;">${b.selectedDate}</td>
      </tr>
      <tr>
        <td style="padding: 6px 0; color: #6b7280;">Ubicación & Dirección:</td>
        <td style="padding: 6px 0; font-weight: 600; color: #111827;">${sanitizeInput(b.canton)}, ${sanitizeInput(b.province)} — ${sanitizeInput(b.address)}</td>
      </tr>
    </table>

    <div style="border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; margin-bottom: 18px;">
      <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
        <thead style="background: #f9fafb; border-bottom: 1px solid #e5e7eb;">
          <tr>
            <th style="padding: 10px; text-align: left; color: #374151;">Concepto / Formato</th>
            <th style="padding: 10px; text-align: left; color: #374151;">Logística Montaje</th>
            <th style="padding: 10px; text-align: right; color: #374151;">Monto</th>
          </tr>
        </thead>
        <tbody>
          <tr style="border-bottom: 1px solid #f3f4f6;">
            <td style="padding: 10px; font-weight: 600;">${sanitizeInput(b.serviceName)}</td>
            <td style="padding: 10px; color: #6b7280; font-size: 11px;">Montaje: ${service ? service.setup_display : "2h antes"}<br>Desmontaje: ${service ? service.teardown_display : "1h después"}</td>
            <td style="padding: 10px; text-align: right; font-weight: 700;">${formatCRC(PriceManager.getServicePrice(service))}</td>
          </tr>
          ${b.extras && b.extras.extraHoursCount > 0 ? `
          <tr style="border-bottom: 1px solid #f3f4f6;">
            <td style="padding: 8px 10px;">• Horas Adicionales de Show (${b.extras.extraHoursCount} hr)</td>
            <td style="padding: 8px 10px; color: #6b7280; font-size: 11px;">Continuación directa</td>
            <td style="padding: 8px 10px; text-align: right;">${formatCRC(b.extras.extraHoursTotal)}</td>
          </tr>` : ""}
          ${b.extras && b.extras.djHoursCount > 0 ? `
          <tr style="border-bottom: 1px solid #f3f4f6;">
            <td style="padding: 8px 10px;">• Servicio de DJ en Recesos (${b.extras.djHoursCount} hr)</td>
            <td style="padding: 8px 10px; color: #6b7280; font-size: 11px;">Mezcla en vivo</td>
            <td style="padding: 8px 10px; text-align: right;">${formatCRC(b.extras.djTotal)}</td>
          </tr>` : ""}
          ${b.extras && b.extras.subwoofersCount > 0 ? `
          <tr style="border-bottom: 1px solid #f3f4f6;">
            <td style="padding: 8px 10px;">• Subwoofers Extra 18" (${b.extras.subwoofersCount} un)</td>
            <td style="padding: 8px 10px; color: #6b7280; font-size: 11px;">Refuerzo acústico</td>
            <td style="padding: 8px 10px; text-align: right;">${formatCRC(b.extras.subwoofersTotal)}</td>
          </tr>` : ""}
          ${b.travelSurcharge > 0 ? `
          <tr style="border-bottom: 1px solid #f3f4f6;">
            <td style="padding: 8px 10px;">• Viáticos de Transporte (Fuera GAM 12%)</td>
            <td style="padding: 8px 10px; color: #6b7280; font-size: 11px;">${sanitizeInput(b.province)}</td>
            <td style="padding: 8px 10px; text-align: right;">+${formatCRC(b.travelSurcharge)}</td>
          </tr>` : ""}
        </tbody>
      </table>
    </div>

    <div style="display: flex; justify-content: flex-end; margin-bottom: 24px;">
      <table style="width: 280px; border-collapse: collapse; font-size: 12px;">
        <tr>
          <td style="padding: 4px 0; color: #6b7280;">Gran Total:</td>
          <td style="padding: 4px 0; text-align: right; font-weight: 800; font-size: 14px;">${formatCRC(b.granTotal)}</td>
        </tr>
        <tr style="border-top: 1px solid #e5e7eb; border-bottom: 1px solid #e5e7eb;">
          <td style="padding: 8px 0; font-weight: 800; color: #059669;">Adelanto SINPE (50%):</td>
          <td style="padding: 8px 0; text-align: right; font-weight: 800; color: #059669; font-size: 14px;">${formatCRC(b.deposit50Amount)}</td>
        </tr>
        <tr>
          <td style="padding: 4px 0; color: #4b5563;">Saldo el Día del Evento:</td>
          <td style="padding: 4px 0; text-align: right; font-weight: 700; color: #4b5563;">${formatCRC(b.remainingBalance)}</td>
        </tr>
      </table>
    </div>

    <div style="border-top: 1px dashed #d1d5db; padding-top: 14px; font-size: 10px; color: #6b7280; line-height: 1.5;">
      <p style="margin: 0 0 4px 0;"><strong>Instrucciones de Pago SINPE Móvil:</strong> Transferir el 50% al número <strong>+506 6227-4984</strong> a nombre de <strong>Juan José Ramírez Chaves</strong>. Enviar comprobante al WhatsApp oficial para validación de agenda.</p>
      <p style="margin: 0;">Ref. SINPE registrada: <strong>${b.sinpeRef || "S/N"}</strong> · Documento de validez comercial emitido por Arkik Productions.</p>
    </div>
  `;

  return container;
}

/**
 * Genera y descarga el voucher oficial de reserva en PDF para el cliente.
 */
function exportVoucherPDF() {
  if (!cart.createdBooking) {
    showToast("No hay una reserva activa para exportar.", "error");
    return;
  }
  const b = cart.createdBooking;
  const container = buildVoucherHtml(b);

  showToast("Generando documento PDF...", "info");

  if (window.html2pdf) {
    const opt = {
      margin: 10,
      filename: `Arkik_Voucher_${b.code}.pdf`,
      image: { type: "jpeg", quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true },
      jsPDF: { unit: "mm", format: "a4", orientation: "portrait" }
    };
    window.html2pdf().set(opt).from(container).save().then(() => {
      showToast("¡Voucher PDF descargado con éxito!", "success");
    }).catch(() => {
      showToast("Error al exportar PDF con html2pdf, abriendo vista de impresión.", "error");
      printFallback(container.innerHTML, `Voucher_${b.code}`);
    });
  } else {
    printFallback(container.innerHTML, `Voucher_${b.code}`);
  }
}

/**
 * Descarga el voucher PDF de una reserva ya registrada (Portal del Propietario).
 */
function downloadBookingVoucher(b) {
  if (!b) {
    showToast("Reserva no encontrada.", "error");
    return;
  }
  const container = buildVoucherHtml(b);
  showToast("Generando voucher PDF...", "info");
  if (window.html2pdf) {
    const opt = {
      margin: 10,
      filename: `Arkik_Voucher_${b.code}.pdf`,
      image: { type: "jpeg", quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true },
      jsPDF: { unit: "mm", format: "a4", orientation: "portrait" }
    };
    window.html2pdf().set(opt).from(container).save().then(() => {
      showToast("¡Voucher PDF descargado con éxito!", "success");
    }).catch(() => {
      showToast("Error al exportar PDF con html2pdf, abriendo vista de impresión.", "error");
      printFallback(container.innerHTML, `Voucher_${b.code}`);
    });
  } else {
    printFallback(container.innerHTML, `Voucher_${b.code}`);
  }
}

/**
 * Busca una reserva por código y exporta su voucher PDF (desde el Portal).
 */
function exportBookingVoucherPDF(code) {
  const booking = BookingStore.find(code);
  if (!booking) {
    showToast("Reserva no encontrada con ese código.", "error");
    return;
  }
  downloadBookingVoucher(booking);
}

/**
 * Exporta el reporte ejecutivo integral en PDF para el Propietario (Juan José Ramírez).
 * Consciente del período seleccionado en el Portal de Staff.
 */
function exportOwnerReportPDF() {
  const filterKey = AdminModule.periodFilter || "total";
  const range = periodRange(filterKey);
  const periodLabel = (PERIOD_FILTERS.find(f => f.key === filterKey) || PERIOD_FILTERS[PERIOD_FILTERS.length - 1]).label;
  const bookings = bookingsInPeriod(filterKey);
  const active = bookings.filter(b => b.status !== "cancelada");
  const total = active.reduce((s, b) => s + b.granTotal, 0);
  const deposits = active.reduce((s, b) => s + b.deposit50Amount, 0);
  const pending = active.reduce((s, b) => s + b.remainingBalance, 0);

  let spanDays = Math.max(1, Math.round((parseISO(range.end) - parseISO(range.start)) / 86400000) + 1);
  if (filterKey === "total") {
    const dates = active.map(b => parseISO(b.selectedDate)).filter(Boolean).sort((a, b) => a - b);
    spanDays = dates.length >= 2 ? Math.max(1, Math.round((dates[dates.length - 1] - dates[0]) / 86400000) + 1) : 1;
  }
  const capacity = spanDays * DEFAULT_MAX_EVENTS_PER_DAY;
  const occupancy = Math.min(100, Math.round((active.length / capacity) * 100));

  const container = document.createElement("div");
  container.style.padding = "24px";
  container.style.fontFamily = "'Helvetica Neue', Helvetica, Arial, sans-serif";
  container.style.color = "#111827";
  container.style.background = "#ffffff";
  container.style.maxWidth = "900px";
  container.style.margin = "0 auto";

  const rowsHtml = bookings.map(b => `
    <tr style="border-bottom: 1px solid #e5e7eb; font-size: 11px;">
      <td style="padding: 6px; font-family: monospace; font-weight: 700;">${b.code}</td>
      <td style="padding: 6px;"><strong>${sanitizeInput(b.clientName)}</strong><br><span style="font-size: 9px; color: #6b7280;">${sanitizeInput(b.clientPhone)}</span></td>
      <td style="padding: 6px;">${sanitizeInput(b.serviceName)}</td>
      <td style="padding: 6px;">${b.selectedDate}</td>
      <td style="padding: 6px;">${sanitizeInput(b.canton)}, ${sanitizeInput(b.province)}</td>
      <td style="padding: 6px; text-align: right; font-weight: 700;">${formatCRC(b.granTotal)}</td>
      <td style="padding: 6px; text-align: right; color: #059669; font-weight: 700;">${formatCRC(b.deposit50Amount)}</td>
      <td style="padding: 6px; text-align: center;"><span style="padding: 2px 6px; border-radius: 4px; font-size: 9px; font-weight: 700; ${b.status === "confirmada" ? "background:#d1fae5;color:#065f46;" : (b.status === "cancelada" ? "background:#fee2e2;color:#991b1b;" : (b.status === "realizada" ? "background:#e0e7ff;color:#3730a3;" : "background:#fef3c7;color:#92400e;"))}">${BOOKING_STATUSES[b.status] || b.status}</span></td>
    </tr>
  `).join("");

  container.innerHTML = `
    <div style="border-bottom: 2px solid #6d28d9; padding-bottom: 12px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;">
      <div>
        <h1 style="margin: 0; font-size: 22px; color: #4c1d95; font-weight: 800;">ARKIK PRODUCTIONS</h1>
        <p style="margin: 2px 0 0 0; font-size: 12px; color: #6b7280;">Reporte Ejecutivo de Operaciones y Flujo Financiero</p>
        <p style="margin: 2px 0 0 0; font-size: 11px; color: #7c3aed; font-weight: 700;">Período: ${periodLabel} · ${range.start} → ${range.end}</p>
      </div>
      <div style="text-align: right; font-size: 11px; color: #4b5563;">
        <p style="margin: 0;"><strong>Propietario:</strong> Juan José Ramírez Chaves</p>
        <p style="margin: 2px 0 0 0;">Generado: ${new Date().toLocaleString("es-CR")}</p>
      </div>
    </div>

    <!-- KPIs -->
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 18px;">
      <div style="background: #f3e8ff; border: 1px solid #d8b4fe; padding: 10px; border-radius: 8px;">
        <span style="font-size: 10px; color: #6b21a8; font-weight: 700; text-transform: uppercase;">Eventos Activos</span>
        <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 800; color: #581c87;">${active.length}</p>
      </div>
      <div style="background: #ecfdf5; border: 1px solid #a7f3d0; padding: 10px; border-radius: 8px;">
        <span style="font-size: 10px; color: #065f46; font-weight: 700; text-transform: uppercase;">Total Cotizado</span>
        <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 800; color: #064e3b;">${formatCRC(total)}</p>
      </div>
      <div style="background: #e0f2fe; border: 1px solid #bae6fd; padding: 10px; border-radius: 8px;">
        <span style="font-size: 10px; color: #075985; font-weight: 700; text-transform: uppercase;">Adelantos 50%</span>
        <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 800; color: #0c4a6e;">${formatCRC(deposits)}</p>
      </div>
      <div style="background: #fdf2f8; border: 1px solid #fbcfe8; padding: 10px; border-radius: 8px;">
        <span style="font-size: 10px; color: #9d174d; font-weight: 700; text-transform: uppercase;">Saldo por Cobrar</span>
        <p style="margin: 4px 0 0 0; font-size: 18px; font-weight: 800; color: #831843;">${formatCRC(pending)}</p>
      </div>
    </div>

    <!-- Tabla -->
    <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 11px;">
      <thead style="background: #f3f4f6; border-bottom: 2px solid #d1d5db;">
        <tr>
          <th style="padding: 8px; text-align: left;">Código</th>
          <th style="padding: 8px; text-align: left;">Cliente</th>
          <th style="padding: 8px; text-align: left;">Formato</th>
          <th style="padding: 8px; text-align: left;">Fecha</th>
          <th style="padding: 8px; text-align: left;">Ubicación</th>
          <th style="padding: 8px; text-align: right;">Gran Total</th>
          <th style="padding: 8px; text-align: right;">Adelanto (50%)</th>
          <th style="padding: 8px; text-align: center;">Estado</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml || '<tr><td colspan="8" style="padding: 12px; text-align: center; color: #9ca3af;">No hay reservas registradas en este período.</td></tr>'}
      </tbody>
    </table>

    <div style="border-top: 1px solid #e5e7eb; padding-top: 10px; font-size: 10px; color: #9ca3af; text-align: right;">
      Ocupación del período: ${occupancy}% (máx. ${DEFAULT_MAX_EVENTS_PER_DAY} eventos/día) · Arkik Productions Costa Rica · Granadilla, San José
    </div>
  `;

  showToast("Generando reporte ejecutivo PDF...", "info");

  if (window.html2pdf) {
    const opt = {
      margin: 8,
      filename: `Arkik_Reporte_Ejecutivo_${periodLabel.replace(/\s+/g, "_")}_${new Date().toISOString().slice(0, 10)}.pdf`,
      image: { type: "jpeg", quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true },
      jsPDF: { unit: "mm", format: "a4", orientation: "landscape" }
    };
    window.html2pdf().set(opt).from(container).save().then(() => {
      showToast("¡Reporte ejecutivo PDF exportado con éxito!", "success");
    }).catch(() => {
      printFallback(container.innerHTML, `Reporte_Ejecutivo_${new Date().toISOString().slice(0, 10)}`);
    });
  } else {
    printFallback(container.innerHTML, `Reporte_Ejecutivo_${new Date().toISOString().slice(0, 10)}`);
  }
}

function printFallback(htmlContent, title) {
  const w = window.open("", "_blank");
  if (!w) {
    showToast("Por favor permita ventanas emergentes para exportar el documento.", "error");
    return;
  }
  w.document.write(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>${title}</title>
        <style>
          body { font-family: sans-serif; margin: 20px; }
          @media print { button { display: none; } }
        </style>
      </head>
      <body>
        <div style="margin-bottom: 20px;">
          <button onclick="window.print()" style="padding: 10px 20px; background: #6d28d9; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold;">Imprimir / Guardar como PDF</button>
        </div>
        ${htmlContent}
      </body>
    </html>
  `);
  w.document.close();
}

// ============================================================
// 10. SPA HASH ROUTING & NAVIGATION GUARDS
// (index.html es el ÚNICO entry point: cero rutas de backend)
// ============================================================

// Rutas hash virtuales que abren los modales SPA (sin navegación de página)
const SPA_ROUTES = {
  "#reserva": "booking",
  "#reservar": "booking",
  "#admin": "admin"
};

// Rutas de backend INEXISTENTES que jamás deben navegar fuera de index.html.
// Si un enlace antiguo o un fallback de servidor apunta a /bookings, /admin, etc.,
// se reescribe internamente a un hash SPA y se abre el modal correspondiente.
const LEGACY_PATH_ROUTES = {
  "/bookings": "#reserva",
  "/booking": "#reserva",
  "/reserva": "#reserva",
  "/reservas": "#reserva",
  "/admin": "#admin",
  "/panel": "#admin"
};

// Normaliza un pathname de backend inexistente (/bookings, /admin...) al hash SPA
// equivalente SIN cambiar de documento ni salir de index.html.
function normalizeSpaPath() {
  const path = (location.pathname || "").replace(/\/+$/, "") || "/";
  const route = LEGACY_PATH_ROUTES[path.toLowerCase()];
  if (!route) return false;
  const base = location.pathname.substring(0, location.pathname.lastIndexOf("/") + 1);
  const target = `${base}index.html${route}${location.search}`;
  if (target !== location.pathname + location.search + location.hash) {
    history.replaceState(null, "", target);
  }
  return true;
}

// Motor de hash routing: #reserva -> modal de cotización, #admin -> panel protegido.
function handleHashRoute() {
  const hash = location.hash || "";
  const route = SPA_ROUTES[hash];
  if (!route) return;

  if (route === "booking") {
    const serviceId = (cart && cart.selectedService && cart.selectedService.id) || 1;
    openBookingModal(serviceId);
    return;
  }
  if (route === "admin") {
    AdminModule.open();
  }
}

// Al cerrar un modal abierto por hash, se limpia el hash para que un refresh
// no reabra el modal de forma inesperada (sin recargar la página).
function clearRouteHashIfNeeded() {
  const hash = location.hash || "";
  if (!SPA_ROUTES[hash]) return;
  const base = location.pathname + location.search;
  history.replaceState(null, "", base);
}

// Intercepta clicks en enlaces internos hacia rutas inexistentes (/bookings, etc.)
// y los redirige al flujo SPA equivalente mediante hash routing.
function guardInternalPathLinks() {
  document.addEventListener("click", (e) => {
    const link = e.target.closest('a[href]');
    if (!link) return;
    const href = link.getAttribute("href") || "";
    if (!/^\/[^/]/.test(href)) return;
    const normalized = href.replace(/\/+$/, "").toLowerCase();
    const route = LEGACY_PATH_ROUTES[normalized];
    if (!route) return;
    e.preventDefault();
    if (location.hash === route) handleHashRoute();
    else location.hash = route;
  });
}

// ============================================================
// 10.5 ANIMATION REGISTRY (Pausa/Reanudación centralizada)
// Pausa todos los motores canvas cuando un modal está abierto:
// libera GPU en móviles y garantiza 60 FPS en el flujo de reserva.
// ============================================================

const AnimationRegistry = {
  engines: new Map(),
  paused: false,

  register(name, handle) {
    if (handle && typeof handle.stop === "function" && typeof handle.start === "function") {
      this.engines.set(name, handle);
    }
  },

  pauseAll() {
    this.paused = true;
    this.engines.forEach(h => h.stop());
  },

  resumeAll() {
    this.paused = false;
    this.engines.forEach(h => h.start());
  }
};

let modalCounter = 0;

function trackModal(open) {
  modalCounter = Math.max(0, modalCounter + (open ? 1 : -1));
  if (modalCounter === 1 && !AnimationRegistry.paused) AnimationRegistry.pauseAll();
  else if (modalCounter === 0 && AnimationRegistry.paused) AnimationRegistry.resumeAll();
}

// ---- Helpers Globales de Interfaz & Clipboard ----

function copyEmailToClipboard(email = "arkikproduc2023@gmail.com") {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(email).then(() => {
      showToast(`Correo copiado al portapapeles: ${email}`, "success");
    }).catch(() => {
      fallbackCopyText(email);
    });
  } else {
    fallbackCopyText(email);
  }
}

function fallbackCopyText(text) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-999999px";
  textArea.style.top = "-999999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand("copy");
    showToast(`Correo copiado al portapapeles: ${text}`, "success");
  } catch (err) {
    showToast(`Correo de contacto: ${text}`, "info");
  }
  if (document.body.contains(textArea)) {
    document.body.removeChild(textArea);
  }
}

// Enlace explícito en window para compatibilidad onclick HTML
window.openAdminLoginModal = () => AdminModule.open();
window.closeAdminLoginModal = () => AdminModule.close();
window.attemptAdminLogin = () => AdminModule.attemptLogin();
window.closeAdminPortalModal = () => AdminModule.closePortal();
window.copyEmailToClipboard = copyEmailToClipboard;
window.openMediaLightbox = openMediaLightbox;
window.closeMediaLightbox = closeMediaLightbox;
window.copyLightboxUrl = copyLightboxUrl;
window.AdminModule = AdminModule;
window.StorageEngine = StorageEngine;

// ============================================================
// 11. GLOBAL APP INSTANCE & BOOT
// ============================================================

const cart = new CartState();

document.addEventListener("DOMContentLoaded", () => {
  initApp();
});

function initApp() {
  // Guarantee no leftover modal/backdrop is visible on boot
  ModalController.closeAll();
  StorageEngine.init();
  normalizeSpaPath();
  renderCatalog(CATALOG_SERVICES);
  renderGalleryFilters();
  renderMediaGallery(StorageEngine.getGalleryItems(), "todos");
  setupEventListeners();
  guardInternalPathLinks();
  populateProvinces();
  restoreBookingToUI();
  initFooterFluidEffect();
  initHeroStringsEffect();
  window.addEventListener("hashchange", handleHashRoute);
  handleHashRoute();
}

// ============================================================
// 12. CATALOG & GALLERY RENDERING
// ============================================================

let currentCatalogCategory = "Todos";

function renderCatalog(services, category = "Todos") {
  const container = document.getElementById("catalog-grid");
  if (!container) return;
  currentCatalogCategory = category;

  const filtered = category === "Todos"
    ? services
    : services.filter(s => s.category === category);

  container.innerHTML = filtered.map(service => `
    <div class="glass-panel rounded-2xl overflow-hidden flex flex-col justify-between group transform hover:-translate-y-2 transition-all duration-300 relative">
      ${service.badge ? `
        <span class="absolute top-4 right-4 z-10 bg-gradient-to-r from-purple-600 to-pink-600 text-white text-xs font-bold px-3 py-1 rounded-full shadow-lg">
          ${sanitizeInput(service.badge)}
        </span>
      ` : ""}

      <div>
        <div class="relative h-56 overflow-hidden">
          <img src="${service.image_url}" alt="${sanitizeInput(service.name)}" class="w-full h-full object-cover group-hover:scale-110 transition-transform duration-300" />
          <div class="absolute inset-0 bg-gradient-to-t from-[#0b0914] via-transparent to-transparent"></div>
          <span class="absolute bottom-3 left-4 text-xs font-semibold px-2.5 py-1 rounded-md bg-purple-950/80 border border-purple-500/40 text-purple-300">
            ${sanitizeInput(service.category)}
          </span>
        </div>

        <div class="p-6">
          <h3 class="text-xl font-bold text-white group-hover:text-purple-300 transition-colors">${sanitizeInput(service.name)}</h3>
          <p class="text-sm text-gray-400 mt-2 line-clamp-3 leading-relaxed">${sanitizeInput(service.description)}</p>

          <div class="mt-4 pt-4 border-t border-purple-500/20 space-y-2">
            <div class="flex items-center text-xs text-purple-300 font-medium">
              <svg class="w-4 h-4 mr-2 text-pink-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
              ${sanitizeInput(service.duration)}
            </div>
            <!-- Operational Logistics Setup & Teardown -->
            <div class="flex items-center text-xs text-emerald-400 font-medium">
              <span class="mr-1.5">⏱️</span>
              <span>Montaje: <strong>${service.setup_display || "2h antes"}</strong> · Desmontaje: <strong>${service.teardown_display || "1h después"}</strong></span>
            </div>
            <div class="flex items-start text-xs text-gray-400">
              <svg class="w-4 h-4 mr-2 text-purple-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
              <span>${sanitizeInput(service.tech_specs)}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="p-6 pt-0">
        <div class="flex items-baseline justify-between mb-4">
          <span class="text-xs text-gray-400 font-medium">Tarifa Base (2 hrs)</span>
          <span class="text-2xl font-extrabold text-gradient-purple">${formatCRC(PriceManager.getServicePrice(service))}</span>
        </div>

        <button onclick="openBookingModal(${service.id})" class="w-full py-3 px-4 rounded-xl font-bold text-white bg-gradient-to-r from-purple-600 via-indigo-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 shadow-lg shadow-purple-900/30 hover:shadow-purple-600/40 transition-all flex items-center justify-center space-x-2">
          <span>Cotizar y Reservar</span>
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"></path></svg>
        </button>
      </div>
    </div>
  `).join("");
}

// ---- Multimedia Gallery (Biblioteca Multimedia & Bento-Grid Showcase) ----

let currentGalleryFilter = "todos";

function renderGalleryFilters(activeKey = "todos") {
  currentGalleryFilter = activeKey;
  const container = document.getElementById("gallery-filters");
  if (!container) return;

  const items = StorageEngine.getGalleryItems();
  const counts = {};
  items.forEach(m => {
    counts[m.category] = (counts[m.category] || 0) + 1;
  });

  container.innerHTML = GALLERY_FILTERS.map(filter => {
    let count;
    if (filter.key === "todos") {
      count = items.length;
    } else if (filter.key === "instagram") {
      count = items.filter(m => m.category === "instagram" || m.type === "instagram").length;
    } else {
      count = counts[filter.key] || 0;
    }

    const active = filter.key === activeKey;
    const base = "gallery-filter-btn min-h-[44px] min-w-[44px] px-4 py-2.5 rounded-xl text-xs sm:text-sm font-bold transition-all duration-300 border flex items-center justify-center gap-1.5 focus:outline-none focus:ring-2 focus:ring-pink-500/50 cursor-pointer";
    const state = active
      ? " bg-gradient-to-r from-purple-600 via-pink-600 to-pink-500 text-white border-transparent shadow-lg shadow-pink-900/40 scale-105"
      : " bg-white/5 text-gray-300 border-white/10 hover:text-white hover:border-pink-500/40 hover:bg-pink-500/10 hover:scale-102";
    return `<button type="button" data-filter="${filter.key}" class="${base}${state}">${sanitizeInput(filter.label)} <span class="text-xs opacity-75 font-semibold bg-black/30 px-1.5 py-0.5 rounded-full">(${count})</span></button>`;
  }).join("");
}

function renderMediaGallery(items, filterKey = "todos") {
  const container = document.getElementById("gallery-grid");
  if (!container) return;

  const filtered = filterKey === "todos"
    ? items
    : items.filter(item => item.category === filterKey || (filterKey === "instagram" && item.type === "instagram"));

  // Smooth fade-in transition
  container.classList.remove("gallery-fade-in");
  void container.offsetWidth;

  container.innerHTML = filtered.map(item => {
    if (item.type === "instagram") {
      return galleryInstagramCard(item);
    } else if (item.type === "video") {
      return galleryVideoCard(item);
    } else {
      return galleryImageCard(item);
    }
  }).join("");

  container.classList.add("gallery-fade-in");
}

function galleryCategoryBadge(item) {
  const label = GALLERY_CATEGORY_LABELS[item.category] || item.category;
  return `
    <span class="px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-[#0a0712]/80 border border-purple-500/30 text-purple-300 backdrop-blur-md shadow-sm">
      ${sanitizeInput(label)}
    </span>
  `;
}

/**
 * Bento-Grid Glassmorphic Instagram Card
 */
function galleryInstagramCard(item) {
  const title = sanitizeInput(item.title);
  const caption = sanitizeInput(item.caption || item.subtitle || "");
  const date = sanitizeInput(item.date || "");
  const safeUrl = sanitizeUrl(item.directUrl || item.url || "https://www.instagram.com/kikeramirezcr");
  const thumbnail = sanitizeUrl(item.thumbnail || "img/Foto Kike .jpg");
  const featuredClass = item.featured ? "sm:col-span-2 lg:col-span-2 bento-card-featured" : "";

  return `
    <article class="gallery-card ${featuredClass} group rounded-3xl overflow-hidden relative block border border-purple-500/20 bg-[#0d0918]/85 backdrop-blur-xl transition-all duration-500 hover:-translate-y-1.5 hover:border-pink-500/50 hover:shadow-[0_0_30px_rgba(236,72,153,0.25)] focus:outline-none focus:ring-2 focus:ring-pink-500/50 cursor-pointer"
             onclick="openMediaLightbox('${item.id}')">
      
      <!-- Media Aspect Ratio Container -->
      <div class="relative ${item.featured ? 'aspect-[16/10] sm:aspect-[16/9]' : 'aspect-[4/5]'} overflow-hidden bg-black/50">
        <!-- Background Image with Micro-zoom -->
        <img src="${thumbnail}" alt="${title}" loading="lazy"
             class="w-full h-full object-cover transition-transform duration-500 ease-out group-hover:scale-105" />

        <!-- Smooth Dark Gradient Overlay -->
        <div class="absolute inset-0 bg-gradient-to-t from-black/95 via-black/40 to-transparent pointer-events-none"></div>

        <!-- Top Badges Bar -->
        <div class="absolute top-3.5 inset-x-3.5 flex items-center justify-between pointer-events-none z-10">
          <div class="flex items-center gap-1.5">
            ${galleryCategoryBadge(item)}
            ${item.featured ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-pink-500/80 text-white border border-pink-400 backdrop-blur-md shadow-sm">⭐ Destacado</span>' : ''}
          </div>
          ${date ? `
            <span class="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-black/60 border border-white/10 text-gray-300 backdrop-blur-md">
              ${date}
            </span>
          ` : ""}
        </div>

        <!-- Center Badge: Authentic Instagram Gradient Pill -->
        <div class="absolute inset-0 flex items-center justify-center pointer-events-none z-10">
          <div class="w-12 h-12 rounded-full bg-gradient-to-tr from-[#f09433] via-[#e6683c] via-[#dc2743] via-[#cc2366] to-[#bc1888] flex items-center justify-center shadow-lg shadow-pink-900/50 group-hover:scale-110 transition-transform duration-300 border border-white/25">
            <svg class="w-6 h-6 text-white drop-shadow-sm" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163c0-3.403-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z"/>
            </svg>
          </div>
        </div>

        <!-- Bottom Typography: Title & Location / Caption -->
        <div class="absolute bottom-0 inset-x-0 p-4 sm:p-5 text-center z-10">
          <h3 class="text-white font-bold text-base sm:text-lg text-center drop-shadow-md leading-tight group-hover:text-pink-200 transition-colors">
            ${title}
          </h3>
          ${caption ? `
            <p class="text-xs text-pink-300 font-medium text-center mt-1.5 flex items-center justify-center gap-1 drop-shadow">
              <svg class="w-3.5 h-3.5 text-pink-400 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z"/>
              </svg>
              <span class="truncate max-w-[280px] sm:max-w-xs">${caption}</span>
            </p>
          ` : ""}
        </div>
      </div>
    </article>
  `;
}

/**
 * Bento-Grid Glassmorphic Video Card
 */
function galleryVideoCard(item) {
  const title = sanitizeInput(item.title);
  const subtitle = sanitizeInput(item.caption || item.subtitle || "");
  const thumbnail = sanitizeUrl(item.thumbnail || "img/Foto Kike .jpg");
  const date = sanitizeInput(item.date || "");
  const featuredClass = item.featured ? "sm:col-span-2 lg:col-span-2 bento-card-featured" : "";

  return `
    <article class="gallery-card ${featuredClass} group relative rounded-3xl overflow-hidden border border-purple-500/20 bg-[#0d0918]/85 backdrop-blur-xl transition-all duration-300 hover:scale-[1.02] hover:border-pink-500/50 hover:shadow-[0_0_30px_rgba(236,72,153,0.25)] cursor-pointer"
             onclick="openMediaLightbox('${item.id}')">
      <div id="gallery-media-${item.id}" class="relative ${item.featured ? 'aspect-[16/10] sm:aspect-[16/9]' : 'aspect-[4/5]'} overflow-hidden bg-black/50">
        <img src="${thumbnail}" alt="${title}" loading="lazy"
          class="w-full h-full object-cover transition-transform duration-500 ease-out group-hover:scale-105" />
        <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/30 to-transparent"></div>
        <div class="absolute top-3.5 inset-x-3.5 flex items-center justify-between z-10">
          <div class="flex items-center gap-1.5">
            ${galleryCategoryBadge(item)}
            ${item.featured ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-pink-500/80 text-white border border-pink-400 backdrop-blur-md shadow-sm">⭐ Destacado</span>' : ''}
          </div>
          ${date ? `<span class="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-black/60 border border-white/10 text-gray-300 backdrop-blur-md">${date}</span>` : ""}
        </div>
        <div class="absolute inset-0 m-auto z-10 w-14 h-14 rounded-full bg-gradient-to-tr from-purple-600 to-pink-500 flex items-center justify-center shadow-2xl shadow-purple-900/60 border border-white/20 backdrop-blur-sm transition-transform duration-300 group-hover:scale-110">
          <span class="absolute inset-0 rounded-full bg-purple-500/40 animate-ping opacity-0 group-hover:opacity-100 [animation-duration:1.6s]"></span>
          <svg class="w-6 h-6 text-white ml-0.5" fill="currentColor" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"></path></svg>
        </div>
        <div class="absolute bottom-0 inset-x-0 p-4 sm:p-5 text-center z-10">
          <h4 class="text-sm sm:text-base font-bold text-white group-hover:text-purple-300 transition-colors leading-snug drop-shadow">${title}</h4>
          ${subtitle ? `<p class="text-xs text-gray-300 mt-1 truncate max-w-[280px] mx-auto">${subtitle}</p>` : ""}
        </div>
      </div>
    </article>
  `;
}

/**
 * Bento-Grid Glassmorphic Image Card
 */
function galleryImageCard(item) {
  const title = sanitizeInput(item.title);
  const subtitle = sanitizeInput(item.caption || item.subtitle || "");
  const url = sanitizeUrl(item.thumbnail || item.directUrl || "img/Foto Kike .jpg");
  const date = sanitizeInput(item.date || "");
  const featuredClass = item.featured ? "sm:col-span-2 lg:col-span-2 bento-card-featured" : "";

  return `
    <article class="gallery-card ${featuredClass} group relative rounded-3xl overflow-hidden border border-purple-500/20 bg-[#0d0918]/85 backdrop-blur-xl transition-all duration-300 hover:scale-[1.02] hover:border-pink-500/50 hover:shadow-[0_0_30px_rgba(236,72,153,0.25)] cursor-pointer"
             onclick="openMediaLightbox('${item.id}')">
      <div class="relative ${item.featured ? 'aspect-[16/10] sm:aspect-[16/9]' : 'aspect-[4/5]'} overflow-hidden bg-black/50">
        <img src="${url}" alt="${title}" loading="lazy"
          class="w-full h-full object-cover transition-transform duration-500 ease-out group-hover:scale-105" />
        <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/30 to-transparent"></div>
        <div class="absolute top-3.5 inset-x-3.5 flex items-center justify-between z-10">
          <div class="flex items-center gap-1.5">
            ${galleryCategoryBadge(item)}
            ${item.featured ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-extrabold bg-pink-500/80 text-white border border-pink-400 backdrop-blur-md shadow-sm">⭐ Destacado</span>' : ''}
          </div>
          ${date ? `<span class="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-black/60 border border-white/10 text-gray-300 backdrop-blur-md">${date}</span>` : ""}
        </div>
        <div class="absolute bottom-0 inset-x-0 p-4 sm:p-5 text-center z-10">
          <h4 class="text-sm sm:text-base font-bold text-white group-hover:text-purple-300 transition-colors leading-snug drop-shadow">${title}</h4>
          ${subtitle ? `<p class="text-xs text-gray-300 mt-1 truncate max-w-[280px] mx-auto">${subtitle}</p>` : ""}
        </div>
      </div>
    </article>
  `;
}

// Lightbox controller state
let activeLightboxUrl = "";

function openMediaLightbox(id) {
  const items = StorageEngine.getGalleryItems();
  const item = items.find(m => String(m.id) === String(id));
  if (!item) return;

  const modal = document.getElementById("mediaLightboxModal");
  const container = document.getElementById("lightbox-media-container");
  const titleEl = document.getElementById("lightbox-title");
  const captionEl = document.getElementById("lightbox-caption");
  const dateEl = document.getElementById("lightbox-date");
  const catEl = document.getElementById("lightbox-category-badge");
  const directLink = document.getElementById("lightbox-direct-link");

  if (titleEl) titleEl.textContent = item.title;
  if (captionEl) captionEl.textContent = item.caption || item.subtitle || "Muestra en vivo oficial de Arkik Productions.";
  if (dateEl) dateEl.textContent = item.date || "2026";
  if (catEl) catEl.textContent = GALLERY_CATEGORY_LABELS[item.category] || item.category;

  activeLightboxUrl = item.directUrl || item.url || "https://www.instagram.com/kikeramirezcr";
  if (directLink) {
    directLink.href = activeLightboxUrl;
  }

  if (container) {
    container.innerHTML = "";
    if (item.type === "video" && item.embedUrl) {
      const iframe = document.createElement("iframe");
      iframe.src = item.embedUrl + (item.embedUrl.includes("?") ? "&" : "?") + "autoplay=1";
      iframe.title = item.title;
      iframe.setAttribute("allow", "accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share");
      iframe.setAttribute("allowfullscreen", "");
      iframe.className = "w-full h-full border-0 rounded-2xl";
      container.appendChild(iframe);
    } else {
      const img = document.createElement("img");
      img.src = item.thumbnail || item.directUrl || "img/Foto Kike .jpg";
      img.alt = item.title;
      img.className = "w-full h-full object-contain max-h-[55vh] rounded-2xl shadow-2xl";
      container.appendChild(img);
    }
  }

  if (modal) {
    ModalController.open("mediaLightboxModal");
  }
}

function closeMediaLightbox() {
  const modal = document.getElementById("mediaLightboxModal");
  const container = document.getElementById("lightbox-media-container");
  if (container) container.innerHTML = ""; // Stop video playback
  if (modal) {
    ModalController.close("mediaLightboxModal");
  }
}

function copyLightboxUrl() {
  const urlToCopy = activeLightboxUrl || "https://www.instagram.com/kikeramirezcr";
  const done = () => showToast("¡Enlace copiado al portapapeles!", "success");
  const fail = () => showToast("No se pudo copiar el enlace.", "error");

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(urlToCopy).then(done).catch(fail);
  } else {
    try {
      const ta = document.createElement("textarea");
      ta.value = urlToCopy;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      ok ? done() : fail();
    } catch (err) {
      fail();
    }
  }
}

// ============================================================
// 13. EVENT LISTENERS
// ============================================================

function setupEventListeners() {
  const filterBtns = document.querySelectorAll(".filter-btn");
  filterBtns.forEach(btn => {
    btn.addEventListener("click", (e) => {
      filterBtns.forEach(b => {
        b.classList.remove("bg-purple-600", "text-white", "shadow-lg");
        b.classList.add("glass-panel", "text-gray-300");
      });
      e.target.classList.remove("glass-panel", "text-gray-300");
      e.target.classList.add("bg-purple-600", "text-white", "shadow-lg");

      const category = e.target.getAttribute("data-category");
      renderCatalog(CATALOG_SERVICES, category);
    });
  });

  const galleryFilters = document.getElementById("gallery-filters");
  if (galleryFilters) {
    galleryFilters.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-filter]");
      if (!btn) return;
      const filterKey = btn.getAttribute("data-filter");
      renderGalleryFilters(filterKey);
      renderMediaGallery(StorageEngine.getGalleryItems(), filterKey);
    });
  }

  const nameInput = document.getElementById("client-name");
  const nameCheck = document.getElementById("name-check");
  if (nameInput && nameCheck) {
    nameInput.addEventListener("input", (e) => {
      const val = e.target.value.trim();
      if (val.length >= 3 && val.length <= 70) {
        nameCheck.classList.remove("hidden");
      } else {
        nameCheck.classList.add("hidden");
      }
    });
  }

  const provSelect = document.getElementById("booking-province");
  if (provSelect) {
    provSelect.addEventListener("change", (e) => {
      cart.province = e.target.value;
      cart.canton = "";
      populateCantones(e.target.value);
      updateSummaryPrices();
      cart.persist();
    });
  }

  const cantonSelect = document.getElementById("booking-canton");
  if (cantonSelect) {
    cantonSelect.addEventListener("change", (e) => {
      cart.canton = e.target.value;
      updateSummaryPrices();
      cart.persist();
    });
  }

  // --- Calendario: Navegación de mes, días y franjas horarias ---
  const calPrev = document.getElementById("cal-prev");
  if (calPrev) calPrev.addEventListener("click", () => CalendarModule.shiftMonth(-1));
  const calNext = document.getElementById("cal-next");
  if (calNext) calNext.addEventListener("click", () => CalendarModule.shiftMonth(1));

  const calGrid = document.getElementById("calendar-grid");
  if (calGrid) {
    calGrid.addEventListener("click", (e) => {
      const day = e.target.closest("[data-date]");
      if (!day || day.disabled) return;
      CalendarModule.selectDate(day.getAttribute("data-date"));
    });
  }

  // --- Admin: Autenticación (Login Ejecutivo FinTech) ---
  const roleOwner = document.getElementById("admin-role-owner");
  if (roleOwner) roleOwner.addEventListener("click", () => AdminModule.setRole("owner"));
  const roleIt = document.getElementById("admin-role-it");
  if (roleIt) roleIt.addEventListener("click", () => AdminModule.setRole("it"));
  const adminPin = document.getElementById("admin-pin");
  if (adminPin) {
    adminPin.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        AdminModule.attemptLogin();
      }
    });
  }
  const pinToggle = document.getElementById("admin-pin-toggle");
  if (pinToggle) {
    pinToggle.addEventListener("click", () => {
      const pin = document.getElementById("admin-pin");
      if (!pin) return;
      const show = pin.type === "password";
      pin.type = show ? "text" : "password";
      pinToggle.setAttribute("aria-pressed", String(show));
      pinToggle.innerHTML = show
        ? `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18"/></svg>`
        : `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/></svg>`;
      pin.focus();
    });
  }
  const loginSubmit = document.getElementById("admin-login-submit");
  if (loginSubmit) loginSubmit.addEventListener("click", () => AdminModule.attemptLogin());
  const closeLoginBtn = document.getElementById("admin-login-close");
  if (closeLoginBtn) closeLoginBtn.addEventListener("click", () => AdminModule.close());
  const loginModal = document.getElementById("adminLoginModal");
  if (loginModal) {
    loginModal.addEventListener("click", (e) => {
      if (e.target === loginModal) AdminModule.close();
    });
  }
  const closePortalBtn = document.getElementById("admin-portal-close");
  if (closePortalBtn) closePortalBtn.addEventListener("click", () => AdminModule.closePortal());
  const portalModal = document.getElementById("adminPortalModal");
  if (portalModal) {
    portalModal.addEventListener("click", (e) => {
      if (e.target === portalModal) AdminModule.closePortal();
    });
    portalModal.addEventListener("pointerdown", () => AdminModule.startInactivityTimer());
    portalModal.addEventListener("keydown", () => AdminModule.startInactivityTimer());
  }
  const logoutBtn = document.getElementById("admin-logout");
  if (logoutBtn) logoutBtn.addEventListener("click", () => AdminModule.logout());

  // --- Admin: Acciones sobre reservas (Propietario) ---
  const bookingsList = document.getElementById("admin-bookings-list");
  if (bookingsList) {
    bookingsList.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-action]");
      if (!btn || btn.disabled) return;
      const row = btn.closest("[data-id]");
      if (!row) return;
      const booking = BookingStore.find(row.getAttribute("data-id"));
      if (!booking) return;

      const action = btn.getAttribute("data-action");
      if (action === "whatsapp") {
        const firstName = String(booking.clientName).split(" ")[0];
        window.open(whatsappClientUrl(booking, `Hola ${firstName}, soy Juan José Ramírez de Arkik Productions. Te contacto para confirmar los detalles de tu evento con código ${booking.code}.`), "_blank", "noopener");
        return;
      }
      if (action === "confirm") {
        BookingStore.updateStatus(booking.code, "confirmada");
        showToast(`Depósito bancario validado. Reserva ${booking.code} confirmada.`, "success");
      } else if (action === "complete") {
        BookingStore.updateStatus(booking.code, "realizada");
        showToast(`Reserva ${booking.code} marcada como realizada.`, "success");
      } else if (action === "cancel") {
        BookingStore.updateStatus(booking.code, "cancelada");
        showToast(`Reserva ${booking.code} cancelada.`, "info");
      } else if (action === "voucher") {
        downloadBookingVoucher(booking);
      }

      AdminModule.renderOwner();
    });
  }

  // --- Admin: Filtros de estado ---
  const statusFilters = document.getElementById("admin-status-filters");
  if (statusFilters) {
    statusFilters.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-filter]");
      if (!btn) return;
      AdminModule.ownerFilter = btn.getAttribute("data-filter");
      AdminModule.renderOwner();
    });
  }

  // --- Admin: Filtros de período (Analítica Financiera) ---
  const periodFilters = document.getElementById("portal-period-filters");
  if (periodFilters) {
    periodFilters.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-period]");
      if (!btn) return;
      AdminModule.periodFilter = btn.getAttribute("data-period");
      AdminModule.renderOwner();
    });
  }

  // --- Admin IT: Pestañas, Disponibilidad, Precios y Respaldo ---
  const itView = document.getElementById("admin-it-view");
  if (itView) {
    itView.addEventListener("click", (e) => {
      const tab = e.target.closest("[data-it-tab]");
      if (tab) {
        AdminModule.setItTab(tab.getAttribute("data-it-tab"));
        return;
      }

      const availBtn = e.target.closest("[data-avail]");
      if (availBtn) {
        const input = document.getElementById("admin-avail-date");
        const iso = input ? input.value : "";
        if (!iso) {
          showToast("Seleccione una fecha primero.", "error");
          return;
        }
        AvailabilityManager.set(iso, availBtn.getAttribute("data-avail"));
        showToast(`Disponibilidad actualizada para ${iso}.`, "success");
        AdminModule.renderIT();
        return;
      }

      const removeBtn = e.target.closest("[data-avail-remove]");
      if (removeBtn) {
        AvailabilityManager.set(removeBtn.getAttribute("data-avail-remove"), "available");
        showToast("Bloqueo manual eliminado.", "success");
        AdminModule.renderIT();
        return;
      }

      if (e.target.closest("#admin-save-prices")) {
        document.querySelectorAll("[data-price]").forEach(input => {
          const key = input.getAttribute("data-price");
          const val = Number(input.value) || 0;
          if (key.startsWith("service-")) {
            PriceManager.setServicePrice(Number(key.split("-")[1]), val);
          } else {
            PriceManager.setExtraPrice(key.split("-")[1], val);
          }
        });

        const extraMultInput = document.getElementById("admin-extra-multiplier");
        if (extraMultInput) {
          const val = parseFloat(extraMultInput.value);
          if (Number.isFinite(val) && val > 0) {
            StorageEngine.setConfig("extraHourMultiplier", val);
          }
        }

        const travelRateInput = document.getElementById("admin-travel-rate");
        if (travelRateInput) {
          const val = parseFloat(travelRateInput.value);
          if (Number.isFinite(val) && val >= 0) {
            StorageEngine.setConfig("travelSurchargeRate", val / 100);
          }
        }

        updateSummaryPrices();
        renderCatalog(CATALOG_SERVICES, currentCatalogCategory);
        AdminModule.renderIT();
        showToast("Precios y configuración actualizados en tiempo real.", "success");
        return;
      }

      if (e.target.closest("#admin-reset-prices")) {
        PriceManager.reset();
        StorageEngine.setConfig("extraHourMultiplier", 0.50);
        StorageEngine.setConfig("travelSurchargeRate", NON_GAM_SURCHARGE_RATE);
        updateSummaryPrices();
        renderCatalog(CATALOG_SERVICES, currentCatalogCategory);
        AdminModule.renderIT();
        showToast("Precios restaurados a los originales.", "success");
        return;
      }

      if (e.target.closest("#admin-export-backup")) {
        exportAdminBackup();
      }
    });

    itView.addEventListener("change", (e) => {
      if (e.target.id === "admin-import-backup" && e.target.files && e.target.files[0]) {
        importAdminBackup(e.target.files[0]);
      }
      e.target.value = "";
    });
  }

  // --- Teclado Global: ESC cierra modales + Ctrl+Shift+A abre panel admin ---
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      const mediaLightbox = document.getElementById("mediaLightboxModal");
      if (mediaLightbox && !mediaLightbox.classList.contains("hidden")) {
        closeMediaLightbox();
        return;
      }
      const adminMediaModal = document.getElementById("adminMediaModal");
      if (adminMediaModal && !adminMediaModal.classList.contains("hidden")) {
        AdminModule.closeMediaModal();
        return;
      }
      const loginModalEl = document.getElementById("adminLoginModal");
      if (loginModalEl && !loginModalEl.classList.contains("hidden")) {
        AdminModule.close();
        return;
      }
      const portalModalEl = document.getElementById("adminPortalModal");
      if (portalModalEl && !portalModalEl.classList.contains("hidden")) {
        AdminModule.closePortal();
        return;
      }
      const execModal = document.getElementById("executive-modal");
      if (execModal && !execModal.classList.contains("hidden")) {
        closeExecutiveModal();
        return;
      }
      const brandModal = document.getElementById("brand-modal");
      if (brandModal && !brandModal.classList.contains("hidden")) {
        closeBrandModal();
        return;
      }
      const modal = document.getElementById("booking-modal");
      if (modal && !modal.classList.contains("hidden")) {
        closeBookingModal();
      }
    }

    if (e.ctrlKey && e.shiftKey && (e.key === "A" || e.key === "a")) {
      e.preventDefault();
      AdminModule.open();
    }
  });
}

// ---- Exportación e Importación de Respaldo (Rol IT) ----

/**
 * Valida el esquema de un payload de backup antes de restaurarlo.
 * Requiere: app === "arkik-productions", código ARK-XXXXXXXX válido por
 * reserva, estados dentro de BOOKING_STATUSES y fechas en formato ISO.
 */
function validateBackupPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { ok: false, error: "El archivo no contiene un objeto de respaldo válido." };
  }
  if (payload.app !== "arkik-productions") {
    return { ok: false, error: "El archivo no pertenece a Arkik Productions." };
  }
  if (payload.bookings && !Array.isArray(payload.bookings)) {
    return { ok: false, error: "Falta la colección de reservas (bookings)." };
  }
  if (payload.availability !== undefined && (typeof payload.availability !== "object" || payload.availability === null)) {
    return { ok: false, error: "El bloque de disponibilidad es inválido." };
  }
  const codeRe = /^ARK-[\dA-Z]{8}$/;
  if (Array.isArray(payload.bookings)) {
    for (const b of payload.bookings) {
      if (!b || typeof b !== "object" || !codeRe.test(b.code || "")) {
        return { ok: false, error: "Reserva con código inválido (se espera ARK-XXXXXXXX)." };
      }
      if (!(b.status in BOOKING_STATUSES)) {
        return { ok: false, error: `Estado desconocido en reserva ${b.code}: ${b.status}.` };
      }
      if (typeof b.selectedDate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(b.selectedDate)) {
        return { ok: false, error: `Fecha inválida en reserva ${b.code}.` };
      }
      if (typeof b.granTotal !== "number" || b.granTotal < 0 || typeof b.deposit50Amount !== "number" || b.deposit50Amount < 0) {
        return { ok: false, error: `Montos inválidos en reserva ${b.code}.` };
      }
    }
  }
  if (payload.availability) {
    for (const [date, state] of Object.entries(payload.availability)) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !["available", "soldout", "disabled"].includes(state)) {
        return { ok: false, error: `Estado de disponibilidad inválido para ${date}.` };
      }
    }
  }
  return { ok: true, error: "" };
}

function exportAdminBackup() {
  const payload = StorageEngine.exportFullDatabase();
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `arkik-database-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  showToast("Base de datos exportada (JSON).", "success");
}

function importAdminBackup(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const payload = JSON.parse(reader.result);
      const validation = validateBackupPayload(payload);
      if (!validation.ok) {
        showToast(`Backup rechazado: ${validation.error}`, "error");
        return;
      }
      StorageEngine.importFullDatabase(payload);
      AdminModule.renderIT();
      renderCatalog(CATALOG_SERVICES, currentCatalogCategory);
      showToast("Respaldo validado e importado. Base de datos restaurada.", "success");
    } catch (err) {
      showToast("Error: archivo de respaldo corrupto o incompatible.", "error");
    }
  };
  reader.onerror = () => showToast("Error al leer el archivo de respaldo.", "error");
  reader.readAsText(file);
}

// ============================================================
// 14. EXECUTIVE & BRAND LIGHTBOXES
// ============================================================

function openExecutiveModal() {
  const modal = document.getElementById("executive-modal");
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.classList.add("flex");
  document.body.style.overflow = "hidden";
}

function closeExecutiveModal() {
  const modal = document.getElementById("executive-modal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  document.body.style.overflow = "";
}

function openBrandModal() {
  const modal = document.getElementById("brand-modal");
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.classList.add("flex");
  document.body.style.overflow = "hidden";
}

function closeBrandModal() {
  const modal = document.getElementById("brand-modal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  document.body.style.overflow = "";
}

function openAdminLoginModal() {
  AdminModule.open();
}

function closeAdminLoginModal() {
  AdminModule.close();
}

function openAdminModal() {
  AdminModule.open();
}

function closeAdminModal() {
  AdminModule.close();
}

function closeAdminPortalModal() {
  AdminModule.closePortal();
}

function attemptAdminLogin() {
  AdminModule.attemptLogin();
}

function adminLogout() {
  AdminModule.logout();
}

// ============================================================
// 14.5 MODAL CONTROLLER (deterministic open/close state machine)
// ============================================================
// Guarantees modals are hidden by default and only revealed on
// explicit user interaction. Wipes any leftover visible state on
// app boot so a rogue backdrop can never black the page out.
const ModalController = {
  _ids: ['booking-modal', 'adminLoginModal', 'adminPortalModal', 'mediaLightboxModal'],

  open(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.remove('hidden', 'opacity-0', 'pointer-events-none', 'invisible');
    modal.classList.add('flex', 'opacity-100', 'pointer-events-auto', 'visible');
    document.body.style.overflow = 'hidden';
  },

  close(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add('hidden', 'opacity-0', 'pointer-events-none', 'invisible');
      modal.classList.remove('flex', 'opacity-100', 'pointer-events-auto', 'visible');
    }
    // Only restore scroll if no other modals are open
    const anyOpen = document.querySelectorAll('#booking-modal.flex, #adminLoginModal.flex, #adminPortalModal.flex, #mediaLightboxModal.flex');
    if (anyOpen.length === 0) {
      document.body.style.overflow = '';
    }
  },

  closeAll() {
    this._ids.forEach(id => this.close(id));
  },

  isOpen(modalId) {
    const modal = document.getElementById(modalId);
    return modal ? !modal.classList.contains('hidden') : false;
  }
};

// ============================================================
// 15. BOOKING WIZARD (4 pasos con micro-interacciones)
// ============================================================

let lastModalStep = 1;

function openBookingModal(serviceId) {
  trackModal(true);
  resetBooking();

  cart.selectedService = CATALOG_SERVICES.find(s => s.id === serviceId) || CATALOG_SERVICES[0];
  cart.persist();

  updateModalStep(1);

  const modal = document.getElementById("booking-modal");
  if (modal) {
    // Pre-mounted modal: deterministic reveal via ModalController
    ModalController.open("booking-modal");
  }

  showToast(`Formato seleccionado: ${cart.selectedService.name}`);
}

function closeBookingModal() {
  const modal = document.getElementById("booking-modal");
  if (modal) {
    ModalController.close("booking-modal");
    resetBooking();
    clearRouteHashIfNeeded();
    trackModal(false);
  }
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
    address: "",
    sinpeRef: "",
    createdBooking: null,
    currentStep: 1,
    isSubmitting: false
  });
  lastModalStep = 1;
  CalendarModule.reset();

  const ids = ["client-name", "client-phone", "client-email", "booking-address", "sinpe-reference", "website_hp"];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  const eventType = document.getElementById("event-type");
  if (eventType) eventType.value = "Boda";

  const prov = document.getElementById("booking-province");
  if (prov) prov.value = "";

  const canton = document.getElementById("booking-canton");
  if (canton) canton.innerHTML = '<option value="">Seleccione primero provincia</option>';

  const voucher = document.getElementById("voucher-view");
  const gateway = document.getElementById("sinpe-gateway-view");
  if (voucher) voucher.classList.add("hidden");
  if (gateway) gateway.classList.remove("hidden");

  // Clear new Step 2 elements
  const logisticsPill = document.getElementById("logistics-pill");
  if (logisticsPill) logisticsPill.classList.add("hidden");
  
  const selectionSummary = document.getElementById("selection-summary");
  if (selectionSummary) selectionSummary.classList.add("hidden");

  cart.clearStoredState();
}

/**
 * Selecciona automáticamente el primer día disponible (>= 72h de antelación) dentro del
 * horizonte de 1 año, según la capacidad diaria de 2 eventos y los bloqueos manuales.
 * Deja la fecha asignada, apunta el calendario al mes correspondiente y habilita el paso 3.
 */
function selectNextAvailableDate() {
  // Punto de partida: hoy + 72h (antelación mínima obligatoria)
  const start = new Date(Date.now() + LOGISTICS_CONFIG.minNoticeHours * 3600 * 1000);
  const { minISO, maxISO } = CalendarModule.getThresholds();
  const baseY = start.getFullYear();
  const baseM = start.getMonth();
  const baseD = start.getDate();

  let foundISO = null;
  // Horizonte operativo: hasta 365 días hacia adelante
  for (let i = 0; i < LOGISTICS_CONFIG.maxHorizonDays; i++) {
    const d = new Date(baseY, baseM, baseD + i);
    const iso = isoOf(d);
    if (iso < minISO || iso > maxISO) continue;

    const override = AvailabilityManager.get(iso);
    if (override === "soldout" || override === "disabled") continue;

    const booked = BookingStore.countForDate(iso);
    if (DEFAULT_MAX_EVENTS_PER_DAY - booked >= 1) {
      foundISO = iso;
      break;
    }
  }

  if (!foundISO) {
    showToast("No hay fechas disponibles en el horizonte de 1 año.", "error");
    return;
  }

  // Asignar fecha seleccionada
  CalendarModule.selectedDate = foundISO;
  cart.selectedDate = foundISO;
  cart.persist();

  // Si el día cae en otro mes, mover el mes/año visible del calendario
  const picked = parseISO(foundISO);
  const view = CalendarModule.viewDate || startOfMonth(new Date());
  if (view.getFullYear() !== picked.getFullYear() || view.getMonth() !== picked.getMonth()) {
    CalendarModule.viewDate = startOfMonth(picked);
  }

  // Re-renderizar el calendario marcando el día como seleccionado
  CalendarModule.render();

  // Actualizar el resumen de selección y el encabezado de fecha
  if (typeof CalendarModule.renderSummary === "function") CalendarModule.renderSummary();
  const header = document.getElementById("selected-date-header");
  if (header) header.textContent = `Fecha: ${foundISO}`;

  // Habilitar de inmediato el botón "Continuar a Ubicación & Datos"
  const continueBtn = document.getElementById("btn-continue-step-2") || document.getElementById("btn-continue-step");
  if (continueBtn) {
    continueBtn.disabled = false;
    continueBtn.classList.remove("opacity-40", "pointer-events-none");
  }

  // Toast sutil con formato DD/MM/AAAA
  const [yy, mm, dd] = foundISO.split("-");
  showToast(`Fecha seleccionada: ${dd}/${mm}/${yy}`, "success");
}

function goToStep(stepNumber) {
  if (stepNumber === 3 && !validateCalendarSelection()) return;

  if (stepNumber === 4) {
    if (isHoneypotTriggered()) return; // neutralización silenciosa de bots
    if (!validateCalendarSelection()) {
      updateModalStep(2);
      return;
    }
    const form = document.getElementById("booking-form-step3");
    if (form && !form.checkValidity()) {
      form.reportValidity();
      updateModalStep(3);
      return;
    }
    if (!validateClientData()) {
      updateModalStep(3);
      return;
    }
    saveClientAndLocationValues();
  }

  cart.currentStep = stepNumber;
  cart.persist();
  updateModalStep(stepNumber);
}

function validateCalendarSelection() {
  if (!cart.selectedDate) {
    showToast("Seleccione una fecha disponible en el calendario.", "error");
    return false;
  }
  return true;
}

function validateClientData() {
  const nameEl = document.getElementById("client-name");
  const nameVal = nameEl ? nameEl.value.trim() : "";
  if (nameVal.length < 3 || nameVal.length > 70) {
    showToast("El nombre o empresa debe tener entre 3 y 70 caracteres.", "error");
    if (nameEl) nameEl.focus();
    return false;
  }

  const phoneEl = document.getElementById("client-phone");
  if (phoneEl && !isValidCRPhone(phoneEl.value)) {
    showToast("Teléfono inválido: use formato 8888-8888 o +506 8888-8888.", "error");
    phoneEl.focus();
    return false;
  }

  const emailEl = document.getElementById("client-email");
  if (emailEl && !isValidRFC5322Email(emailEl.value)) {
    showToast("Ingrese un correo electrónico válido (RFC 5322).", "error");
    emailEl.focus();
    return false;
  }

  return true;
}

function isHoneypotTriggered() {
  const hp = document.getElementById("website_hp");
  return Boolean(hp && hp.value && hp.value.trim() !== "");
}

function saveClientAndLocationValues() {
  cart.clientName = cleanText(document.getElementById("client-name").value, 70);
  cart.clientPhone = cleanText(document.getElementById("client-phone").value, 30);
  cart.clientEmail = cleanText(document.getElementById("client-email").value, 120);
  cart.eventType = cleanText(document.getElementById("event-type").value, 40);
  cart.province = document.getElementById("booking-province").value;
  cart.canton = document.getElementById("booking-canton").value;
  cart.address = cleanText(document.getElementById("booking-address").value, 300);
}

function updateModalStep(stepNumber) {
  const direction = stepNumber > lastModalStep ? "forward" : "backward";
  lastModalStep = stepNumber;

  for (let i = 1; i <= 4; i++) {
    const stepIndicator = document.getElementById(`step-indicator-${i}`);
    const stepPane = document.getElementById(`modal-step-${i}`);

    if (stepIndicator) {
      if (i === stepNumber) {
        stepIndicator.classList.add("border-purple-500", "bg-purple-900/40", "text-purple-300");
        stepIndicator.classList.remove("border-gray-700", "text-gray-500", "border-emerald-500", "text-emerald-400");
      } else if (i < stepNumber) {
        stepIndicator.classList.add("border-emerald-500", "bg-emerald-950/30", "text-emerald-400");
        stepIndicator.classList.remove("border-purple-500", "border-gray-700", "text-gray-500", "bg-purple-900/40");
      } else {
        stepIndicator.classList.remove("border-purple-500", "bg-purple-900/40", "text-purple-300", "border-emerald-500", "text-emerald-400");
        stepIndicator.classList.add("border-gray-700", "text-gray-500");
      }
    }

    if (stepPane) {
      if (i === stepNumber) {
        stepPane.classList.remove("hidden");
        animateStepPane(stepPane, direction);
      } else {
        stepPane.classList.add("hidden");
      }
    }
  }

  // Volver al inicio del contenido del modal en cada transición de paso
  const modalCard = document.getElementById("modal-card");
  if (modalCard) modalCard.scrollTop = 0;

  if (stepNumber === 2) CalendarModule.init();

  if (stepNumber === 2) {
    // Update selection summary card
    const summaryFormat = document.getElementById("summary-format");
    const summaryDate = document.getElementById("summary-date");
    const selectedDateHeader = document.getElementById("selected-date-header");
    const logisticsPill = document.getElementById("logistics-pill");

    if (cart.selectedDate && cart.selectedService) {
      const service = cart.selectedService;
      const dateISO = cart.selectedDate;
      const [y, m, d] = dateISO.split("-").map(Number);
      const monthNames = ["Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"];
      const monthName = monthNames[m - 1];
      const dayName = CALENDAR_LOCALE.weekdays[(new Date(y, m - 1, d).getDay() + 6) % 7];

      if (summaryFormat) summaryFormat.textContent = service.name;
      if (summaryDate) summaryDate.textContent = `${dayName} ${d} de ${monthName} ${y}`;

      if (selectedDateHeader) selectedDateHeader.textContent = `Fecha: ${dateISO}`;

      // Show logistics pill with setup/teardown times from service
      if (logisticsPill) {
        const setupTime = service.setup_display || "2.5 horas antes";
        const teardownTime = service.teardown_display || "1.5 horas después";
        logisticsPill.classList.remove("hidden");
        logisticsPill.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> <span class="text-sm text-purple-200">Montaje ${setupTime} · Desmontaje ${teardownTime}</span>`;
      }
    } else {
      if (logisticsPill) logisticsPill.classList.add("hidden");
    }
  }

  if (stepNumber === 3) {
    const summary = document.getElementById("step3-date-time");
    if (summary) {
      summary.textContent = cart.selectedDate
        ? `${cart.selectedDate}`
        : "Pendiente de selección";
    }
  }

  if (stepNumber === 4) {
    const gateway = document.getElementById("sinpe-gateway-view");
    const voucher = document.getElementById("voucher-view");
    if (gateway && voucher) {
      if (cart.createdBooking) {
        gateway.classList.add("hidden");
        voucher.classList.remove("hidden");
      } else {
        voucher.classList.add("hidden");
        gateway.classList.remove("hidden");
      }
    }
  }

  if (cart.selectedService) {
    document.getElementById("modal-service-name").textContent = cart.selectedService.name;
    document.getElementById("modal-service-price").textContent = formatCRC(PriceManager.getServicePrice(cart.selectedService));
    document.getElementById("modal-service-desc").textContent = cart.selectedService.description;

    const logBox = document.getElementById("modal-service-logistics");
    if (logBox) {
      logBox.innerHTML = `
        <span class="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/40 text-emerald-300">⏱️ Montaje: ${cart.selectedService.setup_display || "2h antes"}</span>
        <span class="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300">🧹 Desmontaje: ${cart.selectedService.teardown_display || "1h después"}</span>
      `;
    }

    renderDynamicExtrasCounters();
    updateSummaryPrices();
  }
}

function animateStepPane(pane, direction) {
  pane.classList.remove("animate-step-in", "animate-step-in-back");
  void pane.offsetWidth;
  pane.classList.add(direction === "forward" ? "animate-step-in" : "animate-step-in-back");
}

// ---- Contadores de Extras Dinámicos ----

function renderDynamicExtrasCounters() {
  const container = document.getElementById("extras-container");
  if (!container) return;

  const extraHourPrice = cart.extraHoursUnitPrice;
  const djPrice = PriceManager.getExtraPrice("dj_service");
  const subPrice = PriceManager.getExtraPrice("subwoofers");

  container.innerHTML = [
    counterRow({
      key: "extraHoursCount",
      name: "Hora(s) Adicional(es) de Show",
      badge: "50% Tarifa Base",
      badgeClass: "bg-purple-900/60 text-purple-300 border border-purple-500/40",
      priceText: `${formatCRC(extraHourPrice)} por hora adicional (50% de ${formatCRC(PriceManager.getServicePrice(cart.selectedService))}) — máx. ${MAX_EXTRAS.extraHoursCount}`,
      value: cart.extraHoursCount,
      max: MAX_EXTRAS.extraHoursCount
    }),
    counterRow({
      key: "djHoursCount",
      name: "Servicio de DJ para Recesos",
      badge: `${formatCRC(djPrice)} / hr`,
      badgeClass: "text-pink-400",
      priceText: "Música continua y mezcla en vivo durante los descansos de la banda",
      value: cart.djHoursCount,
      max: MAX_EXTRAS.djHoursCount
    }),
    counterRow({
      key: "subwoofersCount",
      name: 'Subwoofers Extra de 18"',
      badge: `${formatCRC(subPrice)} / un`,
      badgeClass: "text-pink-400",
      priceText: "Potencia adicional de frecuencias bajas para salones amplios o exteriores",
      value: cart.subwoofersCount,
      max: MAX_EXTRAS.subwoofersCount
    })
  ].join("");
}

function counterRow({ key, name, badge, badgeClass, priceText, value, max }) {
  const atMin = value <= 0;
  const atMax = value >= max;
  const btnBase = "tactile-btn w-8 h-8 rounded-lg bg-purple-900/40 border border-purple-500/30 text-purple-300 font-bold flex items-center justify-center text-lg transition-all";
  const btnDisabled = " opacity-30 cursor-not-allowed";
  return `
    <div class="p-4 rounded-xl glass-panel border border-purple-500/30 flex items-center justify-between">
      <div>
        <div class="flex items-center space-x-2">
          <span class="text-sm font-bold text-white">${sanitizeInput(name)}</span>
          <span class="text-[10px] font-extrabold px-2 py-0.5 rounded ${badgeClass}">${sanitizeInput(badge)}</span>
        </div>
        <p class="text-xs text-gray-400 mt-0.5">${sanitizeInput(priceText)}</p>
      </div>
      <div class="flex items-center space-x-3">
        <button type="button" onclick="adjustExtra('${key}', -1)" ${atMin ? "disabled" : ""} class="${btnBase}${atMin ? btnDisabled : ""}" aria-label="Disminuir ${sanitizeInput(name)}">-</button>
        <span class="text-base font-extrabold text-white w-6 text-center">${value}</span>
        <button type="button" onclick="adjustExtra('${key}', 1)" ${atMax ? "disabled" : ""} class="${btnBase}${atMax ? btnDisabled : ""}" aria-label="Aumentar ${sanitizeInput(name)}">+</button>
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

// ---- Resumen Reactivo de Precios ----

function updateSummaryPrices() {
  document.querySelectorAll(".calc-subtotal").forEach(el => {
    setPriceText(el, formatCRC(cart.subtotal));
  });

  document.querySelectorAll(".calc-gran-total").forEach(el => {
    setPriceText(el, formatCRC(cart.granTotal));
  });

  document.querySelectorAll(".calc-deposit-50").forEach(el => {
    el.textContent = formatCRC(cart.deposit50Amount);
  });

  document.querySelectorAll(".calc-remaining-50").forEach(el => {
    el.textContent = formatCRC(cart.remainingBalance);
  });

  updateSurchargeBox();
}

function updateSurchargeBox() {
  const box = document.getElementById("surcharge-notice-box");
  if (!box) return;
  box.innerHTML = "";

  const div = document.createElement("div");
  div.className = "p-3 rounded-xl border text-xs flex justify-between items-center gap-3";
  const label = document.createElement("span");
  const value = document.createElement("span");
  value.className = "font-bold";

  if (!cart.province) {
    div.classList.add("bg-gray-950/40", "border-gray-600/40", "text-gray-400");
    label.textContent = "Seleccione su provincia para calcular los viáticos de transporte:";
    value.textContent = "Pendiente";
  } else if (!GAM_PROVINCES.includes(cart.province)) {
    div.classList.add("bg-amber-950/40", "border-amber-500/40", "text-amber-300");
    label.textContent = `Recargo del 12% por viáticos fuera del GAM (${cart.province}):`;
    value.textContent = `+${formatCRC(cart.travelSurcharge)}`;
  } else if (!cart.canton) {
    div.classList.add("bg-gray-950/40", "border-gray-600/40", "text-gray-300");
    label.textContent = `${cart.province} está dentro del GAM — seleccione el cantón para confirmar cobertura:`;
    value.textContent = "Pendiente";
  } else if (cart.isNonGam) {
    div.classList.add("bg-amber-950/40", "border-amber-500/40", "text-amber-300");
    label.textContent = `Recargo del 12% por viáticos fuera del GAM (${cart.canton}, ${cart.province}):`;
    value.textContent = `+${formatCRC(cart.travelSurcharge)}`;
  } else {
    div.classList.add("bg-emerald-950/40", "border-emerald-500/40", "text-emerald-300");
    label.textContent = `✓ Cobertura GAM (${cart.canton}, ${cart.province}):`;
    value.textContent = "₡0 (Gratis)";
  }

  box.appendChild(div);
  div.appendChild(label);
  div.appendChild(value);
}

// ---- Provincias & Cantones ----

function populateProvinces() {
  const provSelect = document.getElementById("booking-province");
  if (!provSelect) return;
  provSelect.innerHTML = '<option value="">Seleccione Provincia...</option>' +
    Object.keys(PROVINCES_AND_CANTONES).map(p => `<option value="${sanitizeInput(p)}">${sanitizeInput(p)}</option>`).join("");
}

function populateCantones(province) {
  const cantonSelect = document.getElementById("booking-canton");
  if (!cantonSelect) return;

  const list = (province && PROVINCES_AND_CANTONES[province]) ? PROVINCES_AND_CANTONES[province] : [];
  cantonSelect.innerHTML = '<option value="">Seleccione Cantón...</option>' +
    list.map(c => `<option value="${sanitizeInput(c)}">${sanitizeInput(c)}</option>`).join("");
}

function restoreBookingToUI() {
  if (!cart.province && !cart.canton && !cart.selectedDate && !cart.clientName) return;

  populateProvinces();
  const prov = document.getElementById("booking-province");
  if (prov && cart.province) {
    prov.value = cart.province;
    populateCantones(cart.province);
    const canton = document.getElementById("booking-canton");
    if (canton && cart.canton) canton.value = cart.canton;
  }

  setField("client-name", cart.clientName);
  setField("client-phone", cart.clientPhone);
  setField("client-email", cart.clientEmail);
  setField("event-type", cart.eventType);
  setField("booking-address", cart.address);
  setField("sinpe-reference", cart.sinpeRef);

  if (cart.selectedDate) CalendarModule.init();

  updateSummaryPrices();
}

// ============================================================
// 16. FINALIZACIÓN DE RESERVA & MENSAJES WHATSAPP
// ============================================================

function submitStaticBooking() {
  if (cart.isSubmitting) return;

  if (isHoneypotTriggered()) return; // neutralización silenciosa de bots

  if (!cart.clientName || !cart.clientPhone || !cart.selectedDate || !cart.province || !cart.canton) {
    showToast("Faltan datos obligatorios del evento. Complete el formulario.", "error");
    return;
  }

  const btn = document.getElementById("btn-submit-booking");
  const originalLabel = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = "Generando voucher…";
  }
  cart.isSubmitting = true;

  setTimeout(() => {
    cart.sinpeRef = cleanSinpeRef(document.getElementById("sinpe-reference").value);

    // Código único criptográfico (ARK-XXXXXXXX)
    const bookingCode = generateBookingCode();

    const extrasList = [];
    if (cart.extraHoursCount > 0) extrasList.push(`• Horas Extras: ${cart.extraHoursCount} hr(s) (${formatCRC(cart.extraHoursTotal)})`);
    if (cart.djHoursCount > 0) extrasList.push(`• DJ en Recesos: ${cart.djHoursCount} hr(s) (${formatCRC(cart.djTotal)})`);
    if (cart.subwoofersCount > 0) extrasList.push(`• Subwoofers 18": ${cart.subwoofersCount} un(es) (${formatCRC(cart.subwoofersTotal)})`);

    const extrasFormatted = extrasList.length > 0 ? extrasList.join("\n") : "• Ninguno";

    const surchargeText = cart.isNonGam
      ? `🚚 *Viáticos (12% fuera GAM):* ${formatCRC(cart.travelSurcharge)}`
      : `🚚 *Viáticos (GAM):* ₡0 (Sin Recargo)`;

    const service = cart.selectedService;
    const setupDisplay = service ? service.setup_display : "2h antes";
    const teardownDisplay = service ? service.teardown_display : "1h después";

    const rawMsg =
      `🎸 *ARKIK PRODUCTIONS - RESERVA & COTIZACIÓN*
----------------------------------------
📌 *Código:* ${bookingCode}
👤 *Cliente / Empresa:* ${cart.clientName}
📞 *Teléfono:* ${cart.clientPhone}
✉️ *Email:* ${cart.clientEmail || "No indicado"}
🎉 *Tipo de Evento:* ${cart.eventType}

🎵 *Formato:* ${service.name} (${formatCRC(PriceManager.getServicePrice(service))})
⏱️ *Duración:* ${service.duration}
⚙️ *Logística:* Montaje ${setupDisplay} · Desmontaje ${teardownDisplay}

➕ *EXTRAS COTIZADOS:*
${extrasFormatted}

📅 *Fecha:* ${cart.selectedDate}
📍 *Ubicación:* ${cart.canton}, ${cart.province}
🏠 *Dirección:* ${cart.address}

💰 *Subtotal:* ${formatCRC(cart.subtotal)}
${surchargeText}
✨ *GRAN TOTAL:* ${formatCRC(cart.granTotal)}
----------------------------------------
💳 *ADELANTO SINPE (50%):* ${formatCRC(cart.deposit50Amount)}
🤝 *SALDO DÍA DEL EVENTO:* ${formatCRC(cart.remainingBalance)}
📲 *Destino SINPE:* ${SINPE_CONFIG.phone} (${SINPE_CONFIG.holder})
🔢 *Ref. SINPE:* ${cart.sinpeRef}
🔒 *Estado Inicial:* Pendiente de Aprobación
----------------------------------------
📎 *Importante:* ${SINPE_CONFIG.policyText}
Adjunte el comprobante de transferencia a este chat para confirmar su reserva.`;

    const encodedMsg = encodeURIComponent(rawMsg);
    const whatsappUrl = `https://wa.me/${SINPE_CONFIG.cleanPhone}?text=${encodedMsg}`;

    // Registro persistente en almacén local
    const record = {
      code: bookingCode,
      createdAt: new Date().toISOString(),
      status: "pendiente", // Inicia siempre como Pendiente de Aprobación
      clientName: cart.clientName,
      clientPhone: cart.clientPhone,
      clientEmail: cart.clientEmail,
      eventType: cart.eventType,
      serviceId: service.id,
      serviceName: service.name,
      setupDisplay: setupDisplay,
      teardownDisplay: teardownDisplay,
      selectedDate: cart.selectedDate,
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

    // Actualización del Voucher en el DOM usando textContent (seguridad estricta)
    document.getElementById("confirm-booking-code").textContent = bookingCode;
    const badgeEl = document.getElementById("confirm-booking-badge");
    if (badgeEl) badgeEl.textContent = bookingCode;

    document.getElementById("confirm-client-name").textContent = cart.clientName;
    document.getElementById("confirm-event-type").textContent = cart.eventType;
    document.getElementById("confirm-service-name").textContent = service.name;

    const logInfoEl = document.getElementById("confirm-logistics-info");
    if (logInfoEl) {
      logInfoEl.textContent = `Montaje: ${setupDisplay} · Desmontaje: ${teardownDisplay}`;
    }

    document.getElementById("confirm-event-date").textContent = cart.selectedDate;
    document.getElementById("confirm-location").textContent = `${cart.canton}, ${cart.province}`;
    document.getElementById("confirm-gran-total").textContent = formatCRC(cart.granTotal);
    document.getElementById("confirm-deposit-50").textContent = formatCRC(cart.deposit50Amount);

    const remBalEl = document.getElementById("confirm-remaining-balance");
    if (remBalEl) remBalEl.textContent = formatCRC(cart.remainingBalance);

    const waBtn = document.getElementById("btn-whatsapp-client");
    if (waBtn) waBtn.href = whatsappUrl;

    cart.clearStoredState();

    cart.isSubmitting = false;
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalLabel;
    }

    goToStep(4);
    showToast("¡Voucher y enlace de WhatsApp generados con éxito!", "success");
  }, 200);
}

function finalizeVoucher() {
  closeBookingModal();
  showToast("¡Reserva registrada! Envíenos el comprobante bancario por WhatsApp.", "success");
}

// ============================================================
// 17. TOAST NOTIFICATIONS & CLIPBOARD
// ============================================================

function showToast(message, type = "info") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = "toast-item";
  if (type === "error") toast.classList.add("toast-error");
  if (type === "success") toast.classList.add("toast-success");

  const icons = {
    success: '<svg class="w-5 h-5 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>',
    error: '<svg class="w-5 h-5 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>',
    info: '<svg class="w-5 h-5 text-purple-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
  };

  const iconWrap = document.createElement("span");
  iconWrap.className = "flex-shrink-0";
  iconWrap.innerHTML = icons[type] || icons.info;

  const text = document.createElement("span");
  text.className = "text-xs font-semibold";
  text.textContent = message;

  toast.appendChild(iconWrap);
  toast.appendChild(text);
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("toast-out");
    setTimeout(() => toast.remove(), 300);
  }, 2800);
}

function copySinpeData() {
  const data = `A nombre de: Juan José Ramírez Chaves\nTeléfono: +506 6227-4984`;
  const done = () => showToast("¡Datos SINPE copiados al portapapeles!", "success");
  const fail = () => showToast("No se pudieron copiar los datos.", "error");

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(data).then(done).catch(fail);
  } else {
    try {
      const ta = document.createElement("textarea");
      ta.value = data;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      ok ? done() : fail();
    } catch (err) {
      fail();
    }
  }
}

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
      const ta = document.createElement("textarea");
      ta.value = SINPE_CONFIG.phone;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      ok ? done() : fail();
    } catch (err) {
      fail();
    }
  }
}

function copyBookingCode() {
  const codeEl = document.getElementById("confirm-booking-code");
  if (!codeEl) return;

  const text = codeEl.textContent;
  const done = () => showToast(`Código ${text} copiado al portapapeles.`, "success");
  const fail = () => showToast("No se pudo copiar el código.", "error");

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(fail);
  } else {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      ok ? done() : fail();
    } catch (err) {
      fail();
    }
  }
}

// ============================================================
// 17.5 DYNAMIC CANVAS RESCALING ENGINE (DPR-aware, zoom-proof)
// ============================================================

/**
 * Fábrica modular de reescalado dinámico para los canvas de fondo.
 * - Sincroniza el backing store con container.clientWidth/Height × devicePixelRatio.
 * - ResizeObserver sobre el contenedor padre + window.resize/orientationchange
 *   con debounce (evita thrashing durante gestos y zoom interactivo).
 * - El CSS ancla el canvas con position:absolute inset:0 w/h 100%, por lo que el
 *   render queda cubriendo la sección a cualquier zoom (25%–200%) o pantalla 4K,
 *   eliminando el artefacto de canvas pegado en la esquina superior izquierda.
 */
function createDynamicCanvasController(canvas, container, ctx, onAfterResize) {
  let logicalW = 1;
  let logicalH = 1;

  const resizeCanvas = () => {
    const dpr = Math.max(0.1, Number(window.devicePixelRatio) || 1);
    logicalW = Math.max(1, container.clientWidth);
    logicalH = Math.max(1, container.clientHeight);
    canvas.width = Math.round(logicalW * dpr);
    canvas.height = Math.round(logicalH * dpr);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
    if (typeof onAfterResize === "function") onAfterResize();
  };

  const debounce = (fn, ms) => {
    let timer = null;
    const run = () => {
      clearTimeout(timer);
      timer = setTimeout(fn, ms);
    };
    run.clear = () => clearTimeout(timer);
    return run;
  };

  const debouncedResize = debounce(resizeCanvas, 80);

  let resizeObserver = null;
  if (window.ResizeObserver) {
    resizeObserver = new ResizeObserver(debouncedResize);
    resizeObserver.observe(container);
  }
  window.addEventListener("resize", debouncedResize, { passive: true });
  window.addEventListener("orientationchange", debouncedResize, { passive: true });
  if (window.visualViewport) {
    window.visualViewport.addEventListener("resize", debouncedResize);
  }

  return {
    get width() { return logicalW; },
    get height() { return logicalH; },
    resizeNow: resizeCanvas,
    destroy() {
      debouncedResize.clear();
      if (resizeObserver) resizeObserver.disconnect();
      window.removeEventListener("resize", debouncedResize);
      window.removeEventListener("orientationchange", debouncedResize);
      if (window.visualViewport) {
        window.visualViewport.removeEventListener("resize", debouncedResize);
      }
    }
  };
}

// ============================================================
// 18. FOOTER: FLUID NEON WAVE ENGINE (Canvas 2D, 60 FPS)
// ============================================================

function initFooterFluidEffect() {
  const footer = document.getElementById("site-footer");
  const canvas = document.getElementById("footerFluidCanvas");
  if (!footer || !canvas) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const NEON = ["#a855f7", "#38bdf8", "#10b981", "#ec4899"];
  const RIBBON_COUNT = 3;
  const RIBBON_POINTS = 64;
  const MAX_PARTICLES = 140;

  let logicalW = 0;
  let logicalH = 0;
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
        baseY: (0.28 + i * 0.2 + Math.random() * 0.12) * logicalH,
        amp: (0.02 + Math.random() * 0.018) * logicalH,
        freq: 0.004 + Math.random() * 0.003,
        speed: 0.00022 + Math.random() * 0.00018,
        phase: Math.random() * Math.PI * 2,
        width: 1.6 + Math.random() * 1.4,
        alpha: 0.34 + Math.random() * 0.2
      });
    }
  }

  const canvasController = createDynamicCanvasController(canvas, footer, ctx, () => {
    logicalW = canvasController.width;
    logicalH = canvasController.height;
    buildRibbons();
  });

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
    if (x < 0 || y < 0 || x > logicalW || y > logicalH) return;
    spawnBurst(x, y, 5, 26);
  }

  function scrollBurst() {
    if (!footerInView) return;
    const now = performance.now();
    if (now - lastScrollAt < 260) return;
    lastScrollAt = now;
    for (let i = 0; i < 3; i++) {
      spawnBurst(Math.random() * logicalW, Math.random() * logicalH * 0.4, 4, 40);
    }
  }

  function tick() {
    ctx.clearRect(0, 0, logicalW, logicalH);

    for (const r of ribbons) {
      ctx.beginPath();
      for (let i = 0; i <= RIBBON_POINTS; i++) {
        const x = (i / RIBBON_POINTS) * logicalW;
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
      if (p.life <= 0 || p.y > logicalH + 30) {
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
  }, { rootMargin: "120px" });
  observer.observe(footer);

  footer.addEventListener("pointermove", pointerBurst, { passive: true });
  window.addEventListener("scroll", scrollBurst, { passive: true });

  canvasController.resizeNow();
  start();

  const handle = { start, stop };
  AnimationRegistry.register("footer-fluid", handle);
  return handle;
}

// ============================================================
// 19. HERO: CUERDAS DE GUITARRA NEÓN INTERACTIVAS (Canvas 2D)
// ============================================================

function initHeroStringsEffect() {
  const hero = document.getElementById("hero");
  const canvas = document.getElementById("heroStringsCanvas");
  if (!hero || !canvas) return;

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const NEON = ["#a855f7", "#38bdf8", "#10b981", "#ec4899"];
  const STRING_COUNT = 4;
  const SEGMENTS = 60;
  const DEFLECT_REACH = 140;

  let logicalW = 0;
  let logicalH = 0;
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
        baseY: (0.16 + i * 0.22 + Math.random() * 0.04) * logicalH,
        amp: (0.008 + Math.random() * 0.006) * logicalH,
        freq: 0.006 + Math.random() * 0.004,
        speed: 0.0002 + Math.random() * 0.0002,
        phase: Math.random() * Math.PI * 2,
        width: i === 2 ? 2 : 1.5,
        alpha: i === 3 ? 0.55 : 0.85
      });
    }
  }

  const canvasController = createDynamicCanvasController(canvas, hero, ctx, () => {
    logicalW = canvasController.width;
    logicalH = canvasController.height;
    buildStrings();
  });

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
    if (x < -60 || y < -60 || x > logicalW + 60 || y > logicalH + 60) {
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
    ctx.clearRect(0, 0, logicalW, logicalH);
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
      ctx.lineCap = "round";

      for (let i = 0; i <= SEGMENTS; i++) {
        const fx = i / SEGMENTS;
        const x = fx * logicalW;

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
  }, { rootMargin: "120px" });
  observer.observe(hero);

  window.addEventListener("scroll", onScroll, { passive: true });
  hero.addEventListener("mousemove", onPointerMove, { passive: true });
  hero.addEventListener("touchstart", onPointerMove, { passive: true });
  hero.addEventListener("touchmove", onPointerMove, { passive: true });
  hero.addEventListener("mouseleave", onPointerLeave);
  hero.addEventListener("touchend", onPointerLeave, { passive: true });

  canvasController.resizeNow();
  start();

  const handle = { start, stop };
  AnimationRegistry.register("hero-strings", handle);
  return handle;
}

// ============================================================
// DEFENSIVE DOM LIFECYCLE & INITIALIZATION ENGINE
// ============================================================

// DOMContentLoaded guard - ensure all DOM elements exist before bootstrapping
// Handles case where DOM may already be interactive (e.g., fast loads)
(function() {
  const alreadyFired = document.readyState === 'complete' || document.readyState === 'interactive';

  if (!alreadyFired) {
    // DOM not ready yet - add listener
    document.addEventListener('DOMContentLoaded', () => {
      AppEngine.init();
    });
  } else {
    // DOM already ready - init immediately
    AppEngine.init();
  }
})();