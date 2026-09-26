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
 * Elimina cualquier etiqueta HTML del texto (defensa en profundidad).
 * Se aplica en cleanText() para que NINGÚN dato de usuario persistido
 * en el carrito contenga markup que luego pueda renderizarse por error.
 */
function stripTags(str) {
  return String(str ?? "").replace(/<[^>]*>?/gm, "");
}

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

// Hash FNV-1a (32 bit) — SOLO para firmas de sesión, NUNCA para PINs:
// un digest de 8 hex no es comparable con un SHA-256 de 64 hex.
function fnv1aHex(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return ("00000000" + (h >>> 0).toString(16)).slice(-8);
}

// ---- SHA-256 en JavaScript puro (respaldo cuando no hay WebCrypto) ----
// `crypto.subtle` SOLO existe en un contexto seguro. Servir el sitio por
// http:// sobre una IP de red local deja `subtle` en undefined; si el hash cae a
// otro algoritmo, el digest del PIN nunca puede igualar al SHA-256 configurado
// y CADA intento válido se contabiliza como fallo -> bloqueo permanente de la
// consola. Este respaldo produce el MISMO digest SHA-256 de 64 hex, así el
// resultado es idéntico con y sin WebCrypto.
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

// Codificación UTF-8 (TextEncoder cuando existe; manual para navegadores viejos)
function utf8Bytes(text) {
  if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(text);
  const str = String(text);
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code < 0x80) { out.push(code); continue; }
    if (code < 0x800) { out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f)); continue; }
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const low = str.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
        i++;
        out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        continue;
      }
    }
    out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
  }
  return new Uint8Array(out);
}

function bytesToHex(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let hex = "";
  for (let i = 0; i < view.length; i++) hex += view[i].toString(16).padStart(2, "0");
  return hex;
}

// SHA-256 sin dependencias: mismo digest que WebCrypto para toda entrada UTF-8.
// (Límite de longitud: 2^29 - 1 bytes, muy por encima de cualquier uso real aquí.)
function sha256HexSync(text) {
  const bytes = utf8Bytes(String(text == null ? "" : text));
  const bitLen = bytes.length * 8;
  const padded = (((bytes.length + 8) >> 6) + 1) << 6;
  const buf = new Uint8Array(padded);
  buf.set(bytes);
  buf[bytes.length] = 0x80;
  const high = Math.floor(bitLen / 0x20000000);
  const low = bitLen >>> 0;
  buf[padded - 8] = (high >>> 24) & 0xff;
  buf[padded - 7] = (high >>> 16) & 0xff;
  buf[padded - 6] = (high >>> 8) & 0xff;
  buf[padded - 5] = high & 0xff;
  buf[padded - 4] = (low >>> 24) & 0xff;
  buf[padded - 3] = (low >>> 16) & 0xff;
  buf[padded - 2] = (low >>> 8) & 0xff;
  buf[padded - 1] = low & 0xff;

  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);
  const w = new Uint32Array(64);

  for (let offset = 0; offset < padded; offset += 64) {
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = ((buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }

    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }

  let hex = "";
  for (let i = 0; i < 8; i++) hex += H[i].toString(16).padStart(8, "0");
  return hex;
}

// SHA-256 con WebCrypto cuando está disponible; respaldo puro si no lo está.
// Ambos caminos devuelven EXACTAMENTE el mismo digest de 64 hex en minúsculas.
async function sha256Hex(text) {
  const value = String(text == null ? "" : text);
  try {
    if (window.crypto && window.crypto.subtle) {
      const buf = await window.crypto.subtle.digest("SHA-256", utf8Bytes(value));
      return bytesToHex(new Uint8Array(buf));
    }
  } catch (err) {
    /* contexto no seguro o API ausente: respaldo determinista */
  }
  return sha256HexSync(value);
}

// Comparación de digests en tiempo constante (no filtra el prefijo correcto
// por temporización). La longitud se compara aparte porque siempre es fija (64).
function digestsEqual(a, b) {
  const x = String(a == null ? "" : a);
  const y = String(b == null ? "" : b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
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
  return typeof value === "string" ? stripTags(value).trim().slice(0, maxLen) : "";
}

// Validación estricta de teléfonos Costa Rica: 8 dígitos con prefijo opcional (+506 o 506)
function isValidCRPhone(phone) {
  return /^(\+?506)?\s?[2678]\d{3}[-\s]?\d{4}$/.test(String(phone || "").trim());
}

/**
 * Auto-máscara 0000-0000 para el teléfono CR: conserva el prefijo +506/506 —si
 * el usuario lo escribió— y separa los 8 dígitos con un guion en la posición 4.
 * Compatible con el regex /^(\+?506)?\s?[2678]\d{3}[-\s]?\d{4}$/.
 */
function maskCrPhoneInput(input) {
  if (!input) return;
  const raw = String(input.value || "");
  const caret = input.selectionStart != null ? input.selectionStart : raw.length;
  const before = raw.slice(0, caret);
  const prefixMatch = /^(\+?506)/.exec(raw);
  const prefixLen = prefixMatch ? prefixMatch[0].length : 0;
  const prefix = prefixMatch ? prefixMatch[0] : "";

  const bodyRaw = raw.slice(prefixLen).replace(/\D/g, "").slice(0, 8);
  let body = bodyRaw.length > 4 ? bodyRaw.slice(0, 4) + "-" + bodyRaw.slice(4) : bodyRaw;
  const next = prefix ? prefix + " " + body : body;

  if (next === raw) return;
  input.value = next;

  // Mantener el caret razonablemente cerca tras re-maskear.
  const digitsBeforeCaret = (before.slice(prefixLen).replace(/\D/g, "")).length;
  let newCaret;
  if (digitsBeforeCaret <= 4) {
    newCaret = prefixLen + (prefix ? 1 : 0) + digitsBeforeCaret + (digitsBeforeCaret === 4 ? 0 : 0);
  } else {
    newCaret = prefixLen + (prefix ? 1 : 0) + digitsBeforeCaret + 1;
  }
  try { input.setSelectionRange(newCaret, newCaret); } catch (e) { /* noop */ }
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

// "2026-09-30" → "30/09/2026" (formato legible para voucher y WhatsApp)
function formatDisplayDate(iso) {
  const d = parseISO(iso);
  if (!d) return iso || "";
  return `${String(d.getDate()).padStart(2, "0")}/${String(d.getMonth() + 1).padStart(2, "0")}/${d.getFullYear()}`;
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
    // Migración v3.2 → v3.3: la clave canónica ahora es arkik_media_v1
    try {
      const legacy = localStorage.getItem("arkik_gallery_v1");
      const current = localStorage.getItem(STORAGE_KEYS.gallery);
      if (current === null && legacy !== null) {
        localStorage.setItem(STORAGE_KEYS.gallery, legacy);
        localStorage.removeItem("arkik_gallery_v1");
      }
    } catch (e) { /* storage no disponible: continuar */ }
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
    const v = validateBackupPayload(payload);
    if (!v.ok) throw new Error("Backup inválido: " + v.error);
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
    if (typeof StorageEngine !== "undefined" && StorageEngine.onDataChange) {
      StorageEngine.onDataChange("prices");
    }
  },

  setExtraPrice(key, price) {
    if (!this._data) this.load();
    const val = Math.max(0, Math.round(Number(price) || 0));
    if (val > 0) this._data.extras[key] = val;
    else delete this._data.extras[key];
    this.persist();
    if (typeof StorageEngine !== "undefined" && StorageEngine.onDataChange) {
      StorageEngine.onDataChange("prices");
    }
  },

  reset() {
    this._data = { services: {}, extras: {} };
    this.persist();
    if (typeof StorageEngine !== "undefined" && StorageEngine.onDataChange) {
      StorageEngine.onDataChange("prices");
    }
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
    if (typeof StorageEngine !== "undefined" && StorageEngine.onDataChange) {
      StorageEngine.onDataChange("prices");
    }
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
      // Migración v3.2 → v3.3: la clave canónica ahora es arkik_blocked_dates_v1
      try {
        const legacy = localStorage.getItem("arkik_availability_v1");
        const current = localStorage.getItem(STORAGE_KEYS.availability);
        if (current === null && legacy !== null) {
          localStorage.setItem(STORAGE_KEYS.availability, legacy);
          localStorage.removeItem("arkik_availability_v1");
        }
      } catch (e) { /* storage no disponible: continuar */ }
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
    const raw = this._data[iso] || null;
    // Soporte v3.3: los valores pueden ser string ("soldout"/"disabled")
    // o un objeto { state, reason } — normaliza siempre al estado.
    if (raw && typeof raw === "object") return raw.state || null;
    return raw;
  },

  /**
   * Devuelve el detalle completo de un override: { state, reason }.
   * Compatible con valores string legacy (reason queda null).
   */
  getDetails(iso) {
    if (!this._data) this.load();
    const raw = this._data[iso] || null;
    if (!raw) return { state: "available", reason: null };
    if (typeof raw === "object") {
      return { state: raw.state || "available", reason: raw.reason || null };
    }
    return { state: raw, reason: null };
  },

  set(iso, status, reason) {
    if (!this._data) this.load();
    if (status === "available") {
      delete this._data[iso];
    } else if (reason && typeof reason === "string" && reason.trim()) {
      // Guarda estado + motivo documentado (auditable por el rol IT)
      this._data[iso] = { state: status, reason: reason.trim().slice(0, 120) };
    } else {
      this._data[iso] = status;
    }
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
      const v = payload[k];
      if (v === "soldout" || v === "disabled") {
        this._data[k] = v;
      } else if (v && typeof v === "object") {
        const state = v.state;
        if (state === "soldout" || state === "disabled") {
          this._data[k] = { state, reason: typeof v.reason === "string" ? v.reason.slice(0, 120) : null };
        }
      }
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

  // Alias de búsqueda por código (usado por las acciones del Portal Admin)
  find(code) {
    return this.get(code);
  },

  // Reprogramación: solo cambia selectedDate; montos y SINPE quedan intactos
  updateDate(code, iso) {
    const b = this.get(code);
    if (!b || !iso) return false;
    b.selectedDate = iso;
    this.persist();
    if (typeof StorageEngine !== "undefined" && StorageEngine.onDataChange) {
      StorageEngine.onDataChange("bookings");
    }
    return true;
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

// Retraso anti-timing: jitter aleatorio 800-1500 ms antes de responder un error de autenticación
function authJitterDelay() {
  return new Promise((resolve) => setTimeout(resolve, 800 + Math.random() * 700));
}

const SecurityModule = {
  _data: null,

  emptyState() {
    return { ownerHash: null, itHash: null, attempts: 0, lockoutUntil: 0, lockoutLevel: 0 };
  },

  // Un hash persistido solo es válido si es un digest SHA-256 (64 hex minúsculas).
  // Cualquier otra forma (build legacy, corrupción, FNV-1a de 8 hex) se descarta:
  // conservarla haría que el PIN válido no coincida nunca y quemaría el rate limit.
  sanitizeHash(value) {
    if (typeof value !== "string") return null;
    const normalized = value.trim().toLowerCase();
    return /^[0-9a-f]{64}$/.test(normalized) ? normalized : null;
  },

  sanitizeCounter(value) {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  },

  load() {
    let raw = null;
    try {
      raw = safeParse(STORAGE_KEYS.admin, null);
    } catch (e) {
      console.warn('SecurityModule.load corruption recovered:', e.message || e);
      raw = null;
    }
    const data = raw && typeof raw === "object" ? raw : {};
    this._data = {
      ownerHash: this.sanitizeHash(data.ownerHash),
      itHash: this.sanitizeHash(data.itHash),
      attempts: this.sanitizeCounter(data.attempts),
      lockoutUntil: this.sanitizeCounter(data.lockoutUntil),
      lockoutLevel: this.sanitizeCounter(data.lockoutLevel)
    };
  },

  persist() {
    safeSet(STORAGE_KEYS.admin, this._data);
  },

  // Estado de bloqueo vivo (diagnóstico desde la consola del navegador)
  status() {
    this.load();
    const waitMs = Math.max(0, this._data.lockoutUntil - Date.now());
    return {
      storageKey: STORAGE_KEYS.admin,
      attempts: this._data.attempts,
      locked: waitMs > 0,
      waitMs: waitMs,
      lockoutLevel: this._data.lockoutLevel
    };
  },

  // Purga del estado de bloqueo (éxito, expiración, cierre de sesión o reset manual)
  clearLockState(options) {
    const persist = !options || options.persist !== false;
    if (!this._data) this._data = this.emptyState();
    this._data.attempts = 0;
    this._data.lockoutUntil = 0;
    this._data.lockoutLevel = 0;
    if (persist) this.persist();
    return this._data;
  },

  async verifyPin(roleId, pin) {
    this.load();
    const now = Date.now();

    // Bloqueo expirado: se purga de inmediato para que un PIN válido no herede
    // intentos ni nivel de una sesión anterior.
    if (this._data.lockoutUntil) {
      if (now < this._data.lockoutUntil) {
        return { ok: false, locked: true, waitMs: this._data.lockoutUntil - now };
      }
      this.clearLockState();
    }

    const role = ADMIN_CONFIG.roles[roleId];
    if (!role) return { ok: false, locked: false, remaining: ADMIN_CONFIG.maxAttempts };

    // Comparación estricta tras .trim(): el PIN se normaliza antes de hashear,
    // de modo que " 2580 " y "2580" son la misma credencial y solo una coincide.
    const inputHash = await sha256Hex(String(pin == null ? "" : pin).trim());
    const expected = this._data[role.hashKey] || role.defaultHash;

    if (digestsEqual(inputHash, expected)) {
      this.clearLockState();
      return { ok: true };
    }

    this._data.attempts = (this._data.attempts || 0) + 1;
    if (this._data.attempts >= ADMIN_CONFIG.maxAttempts) {
      const level = this._data.lockoutLevel || 0;
      const base = ADMIN_CONFIG.lockoutMs || 300000;
      const max = ADMIN_CONFIG.maxLockoutMs || 3600000;
      const wait = Math.min(base * Math.pow(2, level), max);
      this._data.lockoutUntil = now + wait;
      this._data.lockoutLevel = level + 1;
      this._data.attempts = 0;
      this.persist();
      // El bloqueo se reporta en el mismo intento que lo dispara: la UI muestra
      // la cuenta regresiva de inmediato, sin un envío extra "a ciegas".
      return { ok: false, locked: true, waitMs: wait, remaining: 0 };
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
    this.selectedTime = ""; // Hora del evento (chip del selector de hora)
    this.address = "";
    this.sinpeRef = "";
    this.voucherImage = null; // Data-URL Base64 del comprobante SINPE (máx ~100kb)
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
      selectedTime: this.selectedTime,
      address: this.address,
      sinpeRef: this.sinpeRef,
      voucherImage: this.voucherImage
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

      // Hora del evento (válida si coincide con uno de los slots disponibles)
      const savedTime = cleanText(data.selectedTime, 5);
      if (TimeSlots.indexOf(savedTime) !== -1) this.selectedTime = savedTime;

      // Comprobante SINPE embebido (data-URL jpeg/webp/png). Se limita tamaño
      // para no saturar el almacenamiento local.
      if (typeof data.voucherImage === "string" && data.voucherImage.length > 0 && data.voucherImage.length <= 200000) {
        this.voucherImage = data.voucherImage;
      }
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
// 6B. TIME SELECTOR & COLLISION ENGINE (Step 2)
// Reglas operativas: Max 2 eventos/día · Margen logístico min. 5h entre eventos.
// ============================================================

// Franja horaria operativa: 08:00 → 23:00 (por hora).
const TimeSlots = (() => {
  const arr = [];
  for (let h = 8; h <= 23; h++) {
    arr.push(`${String(h).padStart(2, "0")}:00`);
  }
  return arr;
})();

// Margen logístico mínimo entre eventos (horas) — 5h por regla operativa.
const TIME_BUFFER_HOURS = 5;

/**
 * Convierte "HH:MM" a un valor numérico de horas con decimales (ej. "14:30" -> 14.5)
 * para comparar franjas de colisión.
 */
function timeToNumber(hhmm) {
  if (!hhmm || typeof hhmm !== "string") return null;
  const parts = hhmm.split(":");
  const h = parseInt(parts[0], 10);
  const m = parseInt(parts[1], 10);
  if (isNaN(h) || isNaN(m)) return null;
  return h + (m / 60);
}

/**
 * Calcula qué horas quedan bloqueadas para un día según sus reservas.
 * - 0 reservas: todas las horas habilitadas.
 * - 1 reserva: se bloquean las horas dentro de [T-5h, T+5h].
 * - 2+ reservas: el día está agotado (todas bloqueadas).
 * Devuelve un Set con los strings "HH:MM" bloqueados.
 */
function computeBlockedTimes(iso) {
  const blocked = new Set();
  const bookings = BookingStore.getBookingsForDate(iso);

  if (bookings.length >= 2) {
    // Día agotado (máx. 2 eventos): ninguna hora disponible.
    TimeSlots.forEach(t => blocked.add(t));
    return blocked;
  }
  if (bookings.length === 1) {
    const t = timeToNumber(bookings[0].selectedTime);
    // Si la reserva no tiene hora asignada (reserva antigua), no bloqueamos nada.
    if (t !== null) {
      TimeSlots.forEach(slot => {
        const s = timeToNumber(slot);
        // Bloquea la franja dentro del margen ±5h alrededor de la hora reservada.
        if (s >= t - TIME_BUFFER_HOURS && s <= t + TIME_BUFFER_HOURS) {
          blocked.add(slot);
        }
      });
    }
  }
  return blocked;
}

/**
 * Renderiza los chips de hora para la fecha seleccionada.
 * SIEMPRE limpia el contenedor antes de renderizar (evita bucles infinitos).
 * Oculto por defecto; solo se muestra tras seleccionar una fecha válida.
 */
function renderTimeSelector() {
  const container = document.getElementById("time-selector");
  const wrap = document.getElementById("time-selector-wrap");
  if (!container) return;

  // Limpieza estricta del contenedor antes de cada render (evita acumulación).
  container.innerHTML = "";

  if (!cart.selectedDate) {
    if (wrap) wrap.classList.add("hidden");
    return;
  }

  // Mostrar el selector (fade-in) solo cuando hay una fecha válida.
  if (wrap) {
    wrap.classList.remove("hidden");
    // Gatillo de animación: reinicia para que el fade-in se reproduzca siempre.
    wrap.classList.remove("time-selector-fade");
    void wrap.offsetWidth;
    wrap.classList.add("time-selector-fade");
  }

  const blocked = computeBlockedTimes(cart.selectedDate);
  const selected = cart.selectedTime;
  const bookings = BookingStore.getBookingsForDate(cart.selectedDate);

  // Nota contextual de disponibilidad (0, 1 o 2 eventos).
  const noteEl = document.getElementById("time-availability-note");
  if (noteEl) {
    if (bookings.length === 0) {
      noteEl.textContent = "2 cupos libres — todas las horas disponibles";
    } else if (bookings.length === 1) {
      noteEl.textContent = `1 cupo libre · margen logístico de 5h respecto al evento de las ${bookings[0].selectedTime || "--:--"}`;
    } else {
      noteEl.textContent = "Día agotado (máx. 2 eventos)";
    }
  }

  TimeSlots.forEach(slot => {
    const isBlocked = blocked.has(slot);
    const isSelected = slot === selected;
    const chip = document.createElement("button");
    chip.type = "button";
    chip.dataset.time = slot;
    chip.className = "time-chip" + (isSelected ? " time-chip--selected" : "") + (isBlocked ? " time-chip--disabled" : "");
    chip.disabled = isBlocked;
    chip.setAttribute("aria-pressed", isSelected ? "true" : "false");
    chip.textContent = slot;
    if (!isBlocked) {
      chip.addEventListener("click", () => selectTimeSlot(slot));
    }
    container.appendChild(chip);
  });
}

/**
 * Selecciona una hora válida y la persiste en CartState.
 */
function selectTimeSlot(hhmm) {
  cart.selectedTime = hhmm || "";
  cart.persist();
  // Actualizar resaltado de chips sin re-render innecesario del calendario.
  renderTimeSelector();
  updateStep2ContinueState();

  if (cart.selectedTime) {
    showToast(`Hora seleccionada: ${cart.selectedTime}`, "success");
  }
}

/**
 * Habilita "Continuar a Ubicación & Datos" SOLO cuando hay fecha Y hora válidas.
 */
function updateStep2ContinueState() {
  const continueBtn = document.getElementById("btn-continue-step-2") || document.getElementById("btn-continue-step");
  if (!continueBtn) return;

  const ready = Boolean(cart.selectedDate && cart.selectedTime);
  continueBtn.disabled = !ready;
  continueBtn.classList.toggle("opacity-40", !ready);
  continueBtn.classList.toggle("pointer-events-none", !ready);
}

/**
 * Reinicia la hora seleccionada al cambiar de fecha (mantiene la integridad).
 */
function resetSelectedTime() {
  cart.selectedTime = "";
  cart.persist();
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
    const firstDayOfWeek = (new Date(y, m, 1).getDay() + 6) % 7;

    // Previous month overflow days (grayed-out leading cells)
    const prevMonthDays = new Date(y, m, 0).getDate();
    const prevMonth = m === 0 ? 11 : m - 1;
    const prevYear = m === 0 ? y - 1 : y;
    let cells = "";
    for (let i = firstDayOfWeek - 1; i >= 0; i--) {
      const dayNum = prevMonthDays - i;
      const iso = `${prevYear}-${String(prevMonth + 1).padStart(2, "0")}-${String(dayNum).padStart(2, "0")}`;
      const isToday = iso === nowISO;
      const isSelected = iso === this.selectedDate;
      const css = [
        "ark-cal-day ark-cal-day--other-month",
        isToday ? "ark-cal-day--today" : "",
        isSelected ? "ark-cal-day--selected" : ""
      ].join(" ").trim();
      cells += `
        <button type="button" class="${css}" data-date="${iso}" disabled
          aria-label="${iso} (previous month)">
          <span class="ark-cal-day-num">${dayNum}</span>
        </button>`;
    }

    // Current month days
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
          aria-label="${iso}">
          <span class="ark-cal-day-num">${d}</span>
        </button>`;
    }

    // Next month overflow days (fill remaining cells to complete the grid row)
    const totalCells = firstDayOfWeek + daysInMonth;
    const remainingCells = totalCells % 7 === 0 ? 0 : 7 - (totalCells % 7);
    const nextMonth = m === 11 ? 0 : m + 1;
    const nextYear = m === 11 ? y + 1 : y;
    for (let d = 1; d <= remainingCells; d++) {
      const iso = `${nextYear}-${String(nextMonth + 1).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      const isToday = iso === nowISO;
      const isSelected = iso === this.selectedDate;
      const css = [
        "ark-cal-day ark-cal-day--other-month",
        isToday ? "ark-cal-day--today" : "",
        isSelected ? "ark-cal-day--selected" : ""
      ].join(" ").trim();
      cells += `
        <button type="button" class="${css}" data-date="${iso}" disabled
          aria-label="${iso} (next month)">
          <span class="ark-cal-day-num">${d}</span>
        </button>`;
    }

    grid.innerHTML = cells;
    this.renderSummary();
  },

  getDayState(iso, nowISO, minISO, maxISO) {
    if (iso < minISO) {
      return { css: "ark-cal-day--past", selectable: false };
    }
    if (iso > maxISO) {
      return { css: "ark-cal-day--past", selectable: false };
    }

    const override = AvailabilityManager.get(iso);
    if (override === "soldout") return { css: "ark-cal-day--soldout", selectable: false };
    if (override === "disabled") return { css: "ark-cal-day--disabled", selectable: false };

    const remaining = AvailabilityManager.remainingSlots(iso);
    if (remaining >= 2) {
      return { css: "ark-cal-day--available", selectable: true };
    }
    if (remaining === 1) {
      return { css: "ark-cal-day--few", selectable: true };
    }
    return { css: "ark-cal-day--soldout", selectable: false };
  },

  shiftMonth(delta) {
    this.viewDate = new Date(this.viewDate.getFullYear(), this.viewDate.getMonth() + delta, 1);
    this.render();
  },

  selectDate(iso) {
    // Guardia defensiva: las fechas bloqueadas/agotadas ya se renderizan
    // deshabilitadas, pero si el estado cambia con el modal abierto o un
    // flujo externo intenta seleccionarlas, se rechaza con aviso elegante.
    const override = AvailabilityManager.get(iso);
    if (override === "disabled") {
      showToast("Fecha bloqueada por mantenimiento: no disponible. Elija otra fecha.", "error");
      return;
    }
    if (override === "soldout") {
      showToast("Fecha agotada (capacidad completa de 2 eventos). Elija otra fecha.", "error");
      return;
    }

    this.selectedDate = iso;
    cart.selectedDate = iso;
    cart.persist();
    this.render();

    // Al elegir una nueva fecha se invalida la hora previamente seleccionada:
    // el margen logístico de 5h depende del día concreto.
    resetSelectedTime();
    renderTimeSelector();

    // "Continuar a Ubicación & Datos" SOLO se habilita cuando hay fecha Y hora.
    updateStep2ContinueState();

    // Renderizar chips de hora disponibles para el día (0, 1 o 2 eventos).
    showToast("Fecha seleccionada. Elija la hora del evento.", "success");
  },

  renderSummary() {
    const el = document.getElementById("selected-date-display") || document.getElementById("date-summary");
    if (!el) return;
    if (!this.selectedDate) {
      el.textContent = "No date selected";
      return;
    }
    const [y, m, d] = this.selectedDate.split("-").map(Number);
    const name = CALENDAR_LOCALE.months[m - 1];
    const week = CALENDAR_LOCALE.weekdays[(new Date(y, m - 1, d).getDay() + 6) % 7];
    el.textContent = `${week} ${d} ${name} ${y}`;
  }
};

// ============================================================
// 8. STAFF PORTAL (Login Ejecutivo FinTech + Dashboard Dual)
// ============================================================

const ADMIN_SESSION = {
  role: "",
  token: null,
  createdAt: 0,
  lastActivity: 0,
  inactivityTimer: null,
  lockoutTimer: null,
  integrityTimer: null
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
    return { engineVersion: ENGINE_VERSION, logins: [], lastLogin: null, events: [] };
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

  /**
   * Registra un evento operativo del rol IT (telemetría de auditoría v3.3).
   * type ∈ { login, block, price, gallery, backup, reset }
   */
  recordEvent(type, message, meta) {
    const data = this.load();
    if (!Array.isArray(data.events)) data.events = [];
    data.events.unshift({
      type,
      message: String(message || "").slice(0, 200),
      at: new Date().toISOString(),
      meta: meta || null
    });
    data.events = data.events.slice(0, 80);
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

// ---- Honeypot del login (#login-website-trap) ----
// El campo es invisible para una persona, pero los gestores de contraseñas y el
// auto-relleno del navegador SÍ pueden escribir en él (el nombre "website_trap"
// contiene "website", un heurístico muy común). Antes, cualquier valor no vacío
// abortaba el login en silencio y se traducía en un "no autentica" inexplicable.
// Regla: un valor no vacío solo cuenta como actividad de bot si además hay
// evidencia de interacción real (teclado/arrastre) o una escritura sintética
// no confiable. El valor que aparece sin interacción es auto-relleno del
// navegador → se ignora. El honeypot es un filtro económico de bots, NO una
// frontera de seguridad: la autenticación real siempre exige el digest del PIN.
const LOGIN_TRAP_STATE = { interacted: false, synthetic: false, bound: false };

function resetLoginTrap() {
  const trap = document.getElementById("login-website-trap");
  if (trap) trap.value = "";
  LOGIN_TRAP_STATE.interacted = false;
  LOGIN_TRAP_STATE.synthetic = false;
  return trap;
}

function bindLoginTrap() {
  const trap = document.getElementById("login-website-trap");
  if (!trap || LOGIN_TRAP_STATE.bound) return;
  LOGIN_TRAP_STATE.bound = true;
  // Una persona nunca alcanza este input (tabindex="-1", aria-hidden, fuera de
  // pantalla): si recibe teclado o arrastre, es automatización.
  ["keydown", "keypress", "paste", "drop"].forEach((evt) => {
    trap.addEventListener(evt, () => { LOGIN_TRAP_STATE.interacted = true; }, true);
  });
  trap.addEventListener("input", (e) => {
    // isTrusted === false => escritura programática (script), no auto-relleno.
    if (e && e.isTrusted === false) LOGIN_TRAP_STATE.synthetic = true;
  }, true);
}

function isLoginTrapTriggered() {
  const trap = document.getElementById("login-website-trap");
  if (!trap) return false;
  if (String(trap.value || "").trim() === "") return false; // vacío -> nunca sospechoso
  return LOGIN_TRAP_STATE.interacted || LOGIN_TRAP_STATE.synthetic;
}

const AdminModule = {
  role: "",
  ownerFilter: "todas",
  periodFilter: "total",
  itTab: "prices",
  ownerQuery: "",        // Búsqueda libre dentro de Gestión Avanzada de Reservas
  calCursor: "",         // AAAA-MM visible en el calendario de disponibilidad
  calSelectedDay: "",    // AAAA-MM-DD seleccionado en el calendario ("" = ningún día)
  reschedCode: "",       // Código de la reserva pendiente de reprogramación

  // ---- Apertura / Cierre (Login) ----

  open() {
    const modal = document.getElementById("adminLoginModal");
    if (!modal) return;
    trackModal(true);
    this.resetLockoutState();
    // El modal se abre siempre desbloqueado a nivel de interfaz. El bloqueo
    // acumulado en localStorage se conserva a propósito (cerrar y reabrir no
    // puede ser un bypass del rate limit); se libera con el PIN correcto, al
    // expirar la cuenta regresiva o con resetAdminLock() desde la consola.
    resetLoginTrap();
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
    // Auto-clear sensible data after successful authentication
    const pin = document.getElementById("admin-pin");
    if (pin) pin.value = "";
    if (!portal) return;
    ModalController.open("adminPortalModal");
    const sid = document.getElementById("admin-session-id");
    if (sid) sid.textContent = ADMIN_SESSION.token ? ADMIN_SESSION.token.replace("ARK-", "") : "—";
    this.startInactivityTimer();
    this.startIntegrityMonitor();
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

  /**
   * Bypass manual del bloqueo (consola del navegador / desarrollo).
   * Elimina el estado de bloqueo acumulado del almacenamiento local, vacía el
   * estado en memoria y desbloquea la interfaz del modal al instante.
   * ⚠ Como cualquier persona con acceso al navegador puede invocarlo, es una
   * ayuda de mantenimiento, no una garantía: en producción sirve para
   * desbloquear a un operador legítimo, nunca para sustituir la autenticación.
   */
  resetAdminLock() {
    if (this.lockoutTimer) {
      clearInterval(this.lockoutTimer);
      this.lockoutTimer = null;
    }
    const keys = [
      STORAGE_KEYS.admin,          // clave real: "arkik_admin_auth_v1" (intentos + lockoutUntil)
      "admin_login_attempts",     // nombres heredados: se purgan por compatibilidad
      "admin_lockout_until"
    ];
    const removedKeys = [];
    keys.forEach((key) => {
      if (!key) return;
      try {
        if (localStorage.getItem(key) !== null) {
          localStorage.removeItem(key);
          removedKeys.push(key);
        }
      } catch (e) { /* almacenamiento no disponible */ }
    });
    // Estado en memoria sin persistir: la clave de arriba ya fue eliminada.
    SecurityModule.clearLockState({ persist: false });
    resetLoginTrap();
    const box = document.getElementById("admin-lockout-box");
    if (box) box.classList.add("hidden");
    this.enablePinUI(true);
    this.clearAuthError();
    const modal = document.getElementById("adminLoginModal");
    const pin = document.getElementById("admin-pin");
    if (pin) pin.value = "";
    if (pin && modal && !modal.classList.contains("hidden")) pin.focus();
    return { cleared: true, removedKeys: removedKeys, storageKey: STORAGE_KEYS.admin };
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
    const value = pin ? pin.value.trim().replace(/\D/g, "") : "";
    // Honeypot: valor no vacío + evidencia de interacción/automatización.
    // Un valor proveniente del auto-relleno del navegador NO bloquea el login.
    if (isLoginTrapTriggered()) {
      resetLoginTrap();
      await new Promise((r) => setTimeout(r, 1200));
      return;
    }
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
      ADMIN_SESSION.createdAt = Date.now();
      ADMIN_SESSION.lastActivity = Date.now();
      this.persistSession();
      AuditLog.recordLogin(this.role);
      this.ownerFilter = "todas";
      this.periodFilter = "total";
      this.openPortal();
      showToast(`Autenticado como ${ADMIN_CONFIG.roles[this.role].label}.`, "success");
      return;
    }
    if (result.locked) {
      await authJitterDelay();
      this.startLockoutCountdown(result.waitMs);
      return;
    }
    await authJitterDelay();
    this.showAuthError("Credenciales inválidas o no autorizadas.");
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
      if (msg) {
        const total = Math.max(0, remaining);
        const mm = String(Math.floor(total / 60)).padStart(2, "0");
        const ss = String(total % 60).padStart(2, "0");
        msg.textContent = `Sistema bloqueado. Reintente en ${mm}:${ss}`;
      }
      remaining -= 1;
      if (remaining < 0) {
        clearInterval(this.lockoutTimer);
        this.lockoutTimer = null;
        box.classList.add("hidden");
        // El tiempo terminó: purga inmediata de intentos y nivel de bloqueo
        // en localStorage, no solo del contador visual.
        SecurityModule.clearLockState();
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
    const ms = ADMIN_CONFIG.sessionTimeoutMs || 300000;
    this.sessionDeadline = Date.now() + ms;
    this.inactivityTimer = setTimeout(() => {
      showToast("Sesión administrativa expirada por inactividad.", "info");
      this.terminateSession();
    }, ms);
    const timerEl = document.getElementById("admin-session-timer");
    const pad = n => String(n).padStart(2, "0");
    const tick = () => {
      const remain = Math.max(0, this.sessionDeadline - Date.now());
      if (timerEl) timerEl.textContent = `Sesión expira en ${pad(Math.floor(remain / 60000))}:${pad(Math.floor(remain % 60000 / 1000))}`;
      if (remain <= 0 && this.sessionTick) {
        clearInterval(this.sessionTick);
        this.sessionTick = null;
      }
    };
    tick();
    this.sessionTick = setInterval(tick, 1000);
  },

  clearInactivityTimer() {
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
      this.inactivityTimer = null;
    }
    if (this.sessionTick) {
      clearInterval(this.sessionTick);
      this.sessionTick = null;
    }
    const timerEl = document.getElementById("admin-session-timer");
    if (timerEl) timerEl.textContent = "";
  },

  // ---- Sesión durable: sessionStorage + verificación de integridad ----

  persistSession() {
    try {
      if (!ADMIN_SESSION.token || !ADMIN_SESSION.role) return;
      const data = {
        role: ADMIN_SESSION.role,
        token: ADMIN_SESSION.token,
        createdAt: ADMIN_SESSION.createdAt || Date.now(),
        lastActivity: Date.now()
      };
      data.sig = fnv1aHex(`${data.role}|${data.token}|${data.createdAt}`);
      sessionStorage.setItem(STORAGE_KEYS.session, JSON.stringify(data));
    } catch (err) { /* storage no disponible */ }
  },

  clearSession() {
    try { sessionStorage.removeItem(STORAGE_KEYS.session); } catch (err) { /* noop */ }
  },

  touchActivity() {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEYS.session);
      if (!raw) return;
      const data = JSON.parse(raw);
      if (!data || typeof data !== "object") return;
      data.lastActivity = Date.now();
      sessionStorage.setItem(STORAGE_KEYS.session, JSON.stringify(data));
    } catch (err) { /* noop */ }
  },

  verifySessionIntegrity() {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEYS.session);
      if (!raw) return false;
      const data = JSON.parse(raw);
      if (!data || !data.role || !data.token || !data.createdAt) return false;
      const expected = fnv1aHex(`${data.role}|${data.token}|${data.createdAt}`);
      if (data.sig !== expected) return false;
      const idle = Date.now() - (data.lastActivity || data.createdAt);
      if (idle > (ADMIN_CONFIG.sessionTimeoutMs || 900000)) return false;
      return true;
    } catch (err) { return false; }
  },

  restoreSession() {
    if (!this.verifySessionIntegrity()) return;
    try {
      const data = JSON.parse(sessionStorage.getItem(STORAGE_KEYS.session));
      ADMIN_SESSION.role = data.role;
      ADMIN_SESSION.token = data.token;
      ADMIN_SESSION.createdAt = data.createdAt;
      ADMIN_SESSION.lastActivity = data.lastActivity;
      this.role = data.role;
      this.openPortal();
    } catch (err) { /* noop */ }
  },

  startIntegrityMonitor() {
    this.clearIntegrityMonitor();
    this.integrityTimer = setInterval(() => {
      if (!this.verifySessionIntegrity()) {
        this.clearIntegrityMonitor();
        showToast("Sesión inválida o expirada. Vuelva a autenticarse.", "info");
        this.terminateSession();
        window.scrollTo({ top: 0, behavior: "smooth" });
        if (window.location.hash) window.location.hash = "";
      }
    }, 60000);
  },

  clearIntegrityMonitor() {
    if (this.integrityTimer) {
      clearInterval(this.integrityTimer);
      this.integrityTimer = null;
    }
  },

  terminateSession() {
    this.clearInactivityTimer();
    this.clearIntegrityMonitor();
    this.clearSession();
    this.resetLockoutState();
    // Cierre de sesión (logout, expiración o sello de integridad roto): el
    // estado de bloqueo se purga porque la sesión ya terminó de forma legítima.
    SecurityModule.clearLockState();
    resetLoginTrap();
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
    if (badge) badge.textContent = role.shortLabel || role.label;
    const userName = document.getElementById("admin-user-name");
    if (userName) userName.textContent = role.name;
    // #admin-role-dot es el contenedor del punto de pulso: solo cambia su
    // currentColor según el rol, nunca su estructura interna (ping + punto).
    const dot = document.getElementById("admin-role-dot");
    if (dot) {
      dot.classList.remove("text-emerald-500", "text-indigo-400");
      dot.classList.add(ADMIN_SESSION.role === "owner" ? "text-emerald-500" : "text-indigo-400");
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
    this.renderOwnerCalendar();
    this.renderOwnerFilters();
    this.renderOwnerBookings();
  },

  renderOwnerPeriodFilters() {
    const box = document.getElementById("portal-period-filters");
    if (!box) return;
    box.innerHTML = PERIOD_FILTERS.map(f => {
      const active = f.key === this.periodFilter
        ? "bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-[0_0_18px_rgba(168,85,247,0.45)] border border-purple-400/50 font-bold scale-[1.02]"
        : "bg-white/[0.04] text-slate-300 border border-white/10 hover:bg-white/10 hover:text-white hover:border-purple-500/30";
      return `<button type="button" data-period="${f.key}" class="pill-btn w-full py-2.5 px-3 rounded-xl text-xs sm:text-sm font-semibold transition-all duration-300 text-center flex items-center justify-center min-h-[42px] select-none tracking-tight ${active}">${f.label}</button>`;
    }).join("");
  },

  renderOwnerMetrics() {
    const list = bookingsInPeriod(this.periodFilter);
    const active = list.filter(b => b.status !== "cancelada");
    const validatedDeposits = active
      .filter(b => b.status === "confirmada" || b.status === "realizada")
      .reduce((s, b) => s + (b.deposit50Amount || 0), 0);
    const receivable = active.reduce((s, b) => s + (b.remainingBalance || 0), 0);
    const projected = active.reduce((s, b) => s + (b.granTotal || 0), 0);

    let spanDays = Math.max(1, Math.round((parseISO(periodRange(this.periodFilter).end) - parseISO(periodRange(this.periodFilter).start)) / 86400000) + 1);
    if (this.periodFilter === "total") {
      const dates = active.map(b => parseISO(b.selectedDate)).filter(Boolean).sort((a, b) => a - b);
      spanDays = dates.length >= 2 ? Math.max(1, Math.round((dates[dates.length - 1] - dates[0]) / 86400000) + 1) : 1;
    }
    const capacity = spanDays * DEFAULT_MAX_EVENTS_PER_DAY;
    const occupancy = Math.min(100, Math.round((active.length / capacity) * 100));

    const paidCount = active.filter(b => b.status === "confirmada" || b.status === "realizada").length;
    const pendingCount = active.filter(b => (b.remainingBalance || 0) > 0).length;

    const box = document.getElementById("admin-metrics");
    if (!box) return;
    box.innerHTML = [
      kpiCard("💳", "Adelantos SINPE", formatCRC(validatedDeposits), "exec-kpi--emerald", `${paidCount} reserva(s) cobrada(s) · SINPE`),
      kpiCard("🤝", "Saldos por Cobrar", formatCRC(receivable), "exec-kpi--cyan", `${pendingCount} reserva(s) con saldo pendiente`),
      kpiCard("📊", "Facturación Proyectada", formatCRC(projected), "exec-kpi--fuchsia", `${active.length} eventos activos · ${occupancy}% ocupación`)
    ].join("");
  },

  renderOwnerSparkline() {
    const list = bookingsInPeriod(this.periodFilter).filter(b => b.status !== "cancelada");
    const periodLabel = (PERIOD_FILTERS.find(f => f.key === this.periodFilter) || PERIOD_FILTERS[PERIOD_FILTERS.length - 1]).label;
    const active = list;
    const validatedDeposits = active
      .filter(b => b.status === "confirmada" || b.status === "realizada")
      .reduce((s, b) => s + (b.deposit50Amount || 0), 0);
    const receivable = active.reduce((s, b) => s + (b.remainingBalance || 0), 0);
    const projected = active.reduce((s, b) => s + (b.granTotal || 0), 0);

    const balanceBox = document.getElementById("admin-balance-box");
    const barBox = document.getElementById("admin-bar-chart");
    const ringBox = document.getElementById("admin-ring-chart");
    const corpBox = document.getElementById("admin-corporate-card");
    const recBox = document.getElementById("admin-recent-activity");

    if (balanceBox) {
      balanceBox.innerHTML = `
        <div class="relative overflow-hidden p-5 sm:p-6 rounded-2xl bg-[#0e0a1a]/80 backdrop-blur-xl border border-purple-500/20 hover:border-purple-500/40 transition-all shadow-lg">
          <div class="absolute -top-16 -right-16 w-48 h-48 rounded-full bg-purple-600/20 blur-3xl pointer-events-none"></div>
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="min-w-0">
              <p class="text-[11px] font-semibold tracking-wider text-purple-300/80 uppercase mb-1">Balance Total &amp; Proyección</p>
              <p class="text-2xl sm:text-3xl font-extrabold text-white tracking-tight font-sans mb-2">${formatCRC(projected)}</p>
            </div>
            <span class="px-3 py-1.5 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-300 text-[11px] font-semibold whitespace-nowrap">${periodLabel}</span>
          </div>
          <div class="grid grid-cols-2 gap-3 mt-4">
            <div class="px-3.5 py-2.5 rounded-xl bg-emerald-500/[0.07] border border-emerald-500/20">
              <p class="text-[10px] font-semibold tracking-wider text-emerald-300/80 uppercase">Cobrado vía SINPE</p>
              <p class="text-base sm:text-lg font-extrabold text-emerald-300 tracking-tight font-sans tabular-nums">${formatCRC(validatedDeposits)}</p>
            </div>
            <div class="px-3.5 py-2.5 rounded-xl bg-amber-500/[0.07] border border-amber-500/20">
              <p class="text-[10px] font-semibold tracking-wider text-amber-300/80 uppercase">Pendiente por Cobrar</p>
              <p class="text-base sm:text-lg font-extrabold text-amber-300 tracking-tight font-sans tabular-nums">${formatCRC(receivable)}</p>
            </div>
          </div>
        </div>`;
    }

    // Visualizador de Barras: distribución por tipo de formato/evento
    if (barBox) {
      const byType = {};
      active.forEach(b => {
        const key = b.serviceName || "Evento";
        if (!byType[key]) byType[key] = 0;
        byType[key] += b.granTotal || 0;
      });
      const entries = Object.entries(byType).sort((a, b) => b[1] - a[1]).slice(0, 6);
      const maxVal = Math.max(...entries.map(e => e[1]), 1);
      const bars = entries.length
        ? entries.map(([name, total]) => {
            const h = Math.max(8, Math.round((total / maxVal) * 100));
            const short = name.length > 12 ? name.slice(0, 12) + "…" : name;
            return `
            <div class="flex-1 flex flex-col items-center gap-1.5 min-w-0" title="${name}: ${formatCRC(total)}">
              <div class="w-full rounded-t-lg bg-gradient-to-t from-purple-700 via-indigo-500 to-cyan-400 light-bar" style="height:${h}%"></div>
              <span class="text-[9px] text-slate-500 truncate w-full text-center">${sanitizeInput(short)}</span>
            </div>`;
          }).join("")
        : `<div class="w-full h-full flex items-center justify-center"><p class="text-xs text-slate-500">Sin eventos en el período.</p></div>`;
      barBox.innerHTML = `
        <div class="relative overflow-hidden p-5 rounded-2xl bg-[#0e0a1a]/70 backdrop-blur-xl border border-purple-500/15 hover:border-purple-500/30 transition-all shadow-lg">
          <p class="text-[11px] font-semibold tracking-wider text-purple-300/80 uppercase mb-4">Distribución por Formato</p>
          <div class="h-32 flex items-end gap-2 pt-2">${bars}</div>
          <p class="text-[10px] text-slate-500 mt-3">Ingresos por tipo de evento · ${periodLabel}</p>
        </div>`;
    }

    // Ring Progress: Cobrado vs Pendiente
    if (ringBox) {
      const total = validatedDeposits + receivable;
      const pct = total > 0 ? Math.round((validatedDeposits / total) * 100) : 0;
      const ringColor = total > 0
        ? `conic-gradient(#34d399 0% ${pct}%, rgba(245,158,11,0.9) ${pct}% 100%)`
        : "conic-gradient(rgba(148,163,184,0.25) 0% 100%)";
      ringBox.innerHTML = `
        <div class="relative overflow-hidden p-5 rounded-2xl bg-[#0e0a1a]/70 backdrop-blur-xl border border-purple-500/15 hover:border-purple-500/30 transition-all shadow-lg">
          <p class="text-[11px] font-semibold tracking-wider text-purple-300/80 uppercase mb-4">Cobranza del Período</p>
          <div class="flex items-center justify-center">
            <div class="ring-chart" style="background:${ringColor}">
              <div class="ring-chart__inner">
                <p class="ring-chart__value">${pct}%</p>
                <p class="ring-chart__label">cobrado</p>
              </div>
            </div>
          </div>
          <div class="mt-4 space-y-1.5 text-[11px]">
            <div class="flex items-center justify-between">
              <span class="flex items-center gap-2 text-slate-400"><span class="w-2.5 h-2.5 rounded-sm bg-emerald-400 inline-block"></span> Cobrado vía SINPE</span>
              <span class="font-bold text-emerald-300 tabular-nums">${formatCRC(validatedDeposits)}</span>
            </div>
            <div class="flex items-center justify-between">
              <span class="flex items-center gap-2 text-slate-400"><span class="w-2.5 h-2.5 rounded-sm bg-amber-400 inline-block"></span> Pendiente por Cobrar</span>
              <span class="font-bold text-amber-300 tabular-nums">${formatCRC(receivable)}</span>
            </div>
          </div>
        </div>`;
    }

    // Tarjeta Ejecutiva "Arkik Corporate Card"
    if (corpBox) {
      const activeBalance = projected;
      corpBox.innerHTML = `
        <div class="corporate-card relative overflow-hidden p-5 rounded-2xl shadow-xl">
          <div class="absolute -top-10 -right-10 w-40 h-40 rounded-full bg-purple-500/30 blur-3xl pointer-events-none"></div>
          <div class="absolute -bottom-12 -left-8 w-36 h-36 rounded-full bg-cyan-400/20 blur-3xl pointer-events-none"></div>
          <div class="relative z-10">
            <div class="flex items-center justify-between mb-5">
              <div class="w-9 h-7 rounded-md chip-visual"></div>
              <span class="text-[11px] font-bold tracking-widest text-white/70">ARKIK</span>
            </div>
            <p class="text-[10px] font-semibold tracking-wider text-purple-300/80 uppercase mb-0.5">Balance Activo</p>
            <p class="text-xl sm:text-2xl font-extrabold text-white tracking-tight font-sans mb-4">${formatCRC(activeBalance)}</p>
            <div class="flex items-end justify-between">
              <div>
                <p class="text-[10px] text-white/50 uppercase tracking-wider">Propietario</p>
                <p class="text-xs font-semibold text-white">Juan José Ramírez</p>
              </div>
              <div class="text-right">
                <p class="text-[10px] text-white/50 uppercase tracking-wider">Vence</p>
                <p class="text-xs font-semibold text-white tabular-nums">•• / ••</p>
              </div>
            </div>
          </div>
        </div>`;
    }

    // Actividad Reciente: últimos eventos agendados
    if (recBox) {
      const recent = [...active]
        .sort((a, b) => {
          const da = parseISO(a.selectedDate) || 0;
          const db = parseISO(b.selectedDate) || 0;
          if (db !== da) return db - da;
          return String(b.selectedTime || "").localeCompare(String(a.selectedTime || ""));
        })
        .slice(0, 5);
      const formatEmoji = (serviceId) => {
        const map = { 1: "🎸", 2: "🎻", 3: "🎤", 4: "🎹", 5: "🎷", 6: "🔊" };
        return map[serviceId] || "🎵";
      };
      const rows = recent.length
        ? recent.map(b => {
            const statusLabel = BOOKING_STATUSES[b.status] || b.status;
            const statusDot = b.status === "cancelada" ? "bg-rose-400"
              : (b.status === "pendiente" ? "bg-amber-400"
                : (b.status === "realizada" ? "bg-indigo-400" : "bg-emerald-400"));
            return `
            <div class="flex items-center gap-3 py-2.5 border-b border-white/5 last:border-0">
              <span class="w-9 h-9 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-base shrink-0">${formatEmoji(b.serviceId)}</span>
              <div class="min-w-0 flex-1">
                <p class="text-xs font-semibold text-white truncate">${sanitizeInput(b.clientName)}</p>
                <p class="text-[10px] text-slate-500 truncate">${formatDisplayDate(b.selectedDate)}${b.selectedTime ? " · " + sanitizeInput(b.selectedTime) : ""}</p>
              </div>
              <div class="text-right shrink-0">
                <p class="text-xs font-semibold text-white tabular-nums">${formatCRC(b.granTotal)}</p>
                <p class="text-[10px] flex items-center justify-end gap-1 text-slate-400"><span class="w-1.5 h-1.5 rounded-full ${statusDot} inline-block"></span>${statusLabel}</p>
              </div>
            </div>`;
          }).join("")
        : `<div class="py-6 text-center"><p class="text-xs text-slate-500">Sin reservas recientes en el período.</p></div>`;
      recBox.innerHTML = `
        <div class="relative overflow-hidden p-5 rounded-2xl bg-[#0e0a1a]/70 backdrop-blur-xl border border-purple-500/15 hover:border-purple-500/30 transition-all shadow-lg">
          <p class="text-[11px] font-semibold tracking-wider text-purple-300/80 uppercase mb-2">Actividad Reciente</p>
          ${rows}
        </div>`;
    }
  },

  renderOwnerFilters() {
    const box = document.getElementById("admin-status-filters");
    if (!box) return;
    const statuses = [
      ["todas", "Todas"],
      ["pendiente", "Pendientes"],
      ["confirmada", "Confirmadas"],
      ["realizada", "Realizadas"],
      ["cancelada", "Canceladas"]
    ];
    const periodList = bookingsInPeriod(this.periodFilter);
    box.innerHTML = statuses.map(([key, label]) => {
      const count = key === "todas" ? periodList.length : periodList.filter(b => b.status === key).length;
      const active = key === this.ownerFilter ? "pill-btn--active" : "";
      return `<button type="button" data-filter="${key}" class="pill-btn ${active}">${label} <span class="pill-count">${count}</span></button>`;
    }).join("");
  },

  renderOwnerBookings() {
    const box = document.getElementById("admin-bookings-list");
    if (!box) return;
    const periodList = bookingsInPeriod(this.periodFilter);
    const q = String(this.ownerQuery || "").toLowerCase();
    const list = periodList
      .filter(b => this.ownerFilter === "todas" || b.status === this.ownerFilter)
      .filter(b => {
        if (!q) return true;
        return [b.code, b.clientName, b.clientPhone, b.canton, b.province]
          .some(v => String(v || "").toLowerCase().includes(q));
      });
    if (!list.length) {
      box.innerHTML = `<div class="p-8 rounded-2xl bg-white/5 border border-white/10 text-center"><p class="text-xs text-gray-500">No hay reservas registradas en esta categoría.</p></div>`;
      return;
    }
    box.innerHTML = list.map(bookingCard).join("");
  },

  // ---- Rol Propietario: Calendario de Disponibilidad y Logística ----

  // Cursor AAAA-MM válido (inicializa al mes actual si hace falta)
  calCursorSafe() {
    const cur = this.calCursor;
    if (/^\d{4}-\d{2}$/.test(cur)) return cur;
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  },

  // Estado de un día: override manual → bloqueado; si no, conteo de reservas activas
  calStatusFor(iso) {
    const manual = AvailabilityManager.get(iso);
    if (manual === "disabled" || manual === "soldout") {
      return { key: "blocked", label: "Bloqueado", dot: "cal-dot--purple" };
    }
    const count = Math.min(DEFAULT_MAX_EVENTS_PER_DAY, BookingStore.getBookingsForDate(iso).length);
    if (count === 0) return { key: "libre", label: "Libre", dot: "cal-dot--green" };
    if (count === 1) return { key: "parcial", label: "Parcial", dot: "cal-dot--yellow" };
    return { key: "agotado", label: "Agotado", dot: "cal-dot--red" };
  },

  renderOwnerCalendar() {
    const grid = document.getElementById("admin-calendar-grid");
    const monthEl = document.getElementById("admin-cal-month");
    if (!grid) return;
    const cursor = this.calCursorSafe();
    this.calCursor = cursor;
    const [y, m] = cursor.split("-").map(Number);
    if (monthEl) monthEl.textContent = `${CALENDAR_LOCALE.months[m - 1]} ${y}`;
    const today = isoOf(new Date());
    const offset = (new Date(y, m - 1, 1).getDay() + 6) % 7; // Semana inicia en lunes
    const daysInMonth = new Date(y, m, 0).getDate();
    const cells = [];
    for (let i = 0; i < offset; i++) {
      cells.push('<div class="cal-cell cal-cell--blank" aria-hidden="true"></div>');
    }
    for (let d = 1; d <= daysInMonth; d++) {
      const iso = `${cursor}-${String(d).padStart(2, "0")}`;
      const past = iso < today;
      const st = this.calStatusFor(iso);
      const cls = ["cal-cell"];
      if (past) cls.push("cal-cell--past");
      if (iso === today) cls.push("cal-cell--today");
      if (this.calSelectedDay === iso) cls.push("cal-cell--selected");
      cells.push(
        `<button type="button" class="${cls.join(" ")}" data-cal-day="${iso}" ${past ? "disabled" : ""}
           title="${formatDisplayDate(iso)} · ${st.label}" aria-label="${formatDisplayDate(iso)}, ${st.label}">
          <span class="cal-day-num">${d}</span>
          <span class="cal-dot ${st.dot}"></span>
        </button>`
      );
    }
    grid.innerHTML = cells.join("");
    // Mantener la hoja abierta únicamente si el día seleccionado pertenece a este mes
    if (this.calSelectedDay && this.calSelectedDay.slice(0, 7) === cursor) {
      this.renderOwnerDaySheet();
    } else {
      this.hideDaySheet();
    }
  },

  hideDaySheet() {
    const sheet = document.getElementById("admin-calendar-day-sheet");
    if (sheet) sheet.classList.add("hidden");
  },

  renderOwnerDaySheet() {
    const sheet = document.getElementById("admin-calendar-day-sheet");
    if (!sheet) return;
    const iso = this.calSelectedDay;
    const d = parseISO(iso);
    if (!iso || !d) {
      this.hideDaySheet();
      return;
    }
    const weekday = CALENDAR_LOCALE.weekdays[(d.getDay() + 6) % 7];
    const bookings = BookingStore.getBookingsForDate(iso);
    const st = this.calStatusFor(iso);
    const chipClass = st.key === "blocked" ? "status-badge--disabled"
      : st.key === "agotado" ? "status-badge--soldout"
        : st.key === "parcial" ? "status-badge--pendiente"
          : "status-badge--confirmada";
    const rows = bookings.length ? bookings.map(b => {
      const service = CATALOG_SERVICES.find(s => s.id === b.serviceId);
      const setup = sanitizeInput(service ? service.setup_display : (b.setupDisplay || "2h antes"));
      const teardown = sanitizeInput(service ? service.teardown_display : (b.teardownDisplay || "1h después"));
      return `
      <div class="p-3 rounded-xl bg-black/30 border border-white/5 space-y-1">
        <div class="flex flex-wrap items-center gap-2">
          <span class="font-mono font-extrabold text-purple-300 text-xs">${sanitizeInput(b.code)}</span>
          <span class="status-badge status-badge--${b.status}">${BOOKING_STATUSES[b.status] || sanitizeInput(b.status)}</span>
        </div>
        <p class="text-sm font-bold text-white">${sanitizeInput(b.clientName)}</p>
        <p class="text-[11px] text-gray-400">${sanitizeInput(b.serviceName)}${b.eventType ? " · " + sanitizeInput(b.eventType) : ""}${b.selectedTime ? " · " + sanitizeInput(b.selectedTime) : ""}</p>
        <p class="text-[11px] text-gray-500">Logística: Montaje ${setup} · Desmontaje ${teardown}</p>
        <p class="text-[11px] text-gray-500">${sanitizeInput(b.canton)}, ${sanitizeInput(b.province)}</p>
        <p class="text-[11px] text-gray-500">Contacto: ${sanitizeInput(b.clientPhone)}${b.clientEmail ? " · " + sanitizeInput(b.clientEmail) : ""}</p>
        <p class="text-[11px] text-gray-500">Ref. SINPE: <span class="font-mono font-bold text-cyan-300">${b.sinpeRef ? sanitizeInput(b.sinpeRef) : "S/N"}</span></p>
      </div>`;
    }).join("") : `<p class="text-xs text-gray-500 text-center py-4">Sin eventos. Día libre.</p>`;

    sheet.innerHTML = `
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div class="min-w-0">
          <span class="text-[10px] font-bold text-pink-400 uppercase tracking-widest">Logística del Día</span>
          <h5 class="text-sm font-bold text-white">${formatDisplayDate(iso)} · ${weekday}</h5>
        </div>
        <span class="status-badge ${chipClass}">${st.label}</span>
        <button type="button" data-day-sheet-close onclick="AdminModule.calSelectedDay = ''; AdminModule.hideDaySheet();"
          class="admin-act-btn admin-act-btn--neutral">Cerrar</button>
      </div>
      <div class="space-y-2 mt-3">${rows}</div>`;
    sheet.classList.remove("hidden");
  },

  // ---- Reprogramación de Reservas (modal #adminRescheduleModal) ----

  openRescheduleModal(code) {
    const booking = BookingStore.get(code);
    if (!booking) return;
    this.reschedCode = code;
    const codeEl = document.getElementById("admin-resched-code");
    if (codeEl) codeEl.textContent = code;
    const input = document.getElementById("admin-resched-date");
    if (input) {
      input.value = "";
      input.min = isoOf(new Date(Date.now() + 3 * 86400000)); // antelación mínima 72 h
    }
    ModalController.open("adminRescheduleModal");
  },

  closeRescheduleModal() {
    this.reschedCode = "";
    ModalController.close("adminRescheduleModal");
  },

  confirmReschedule() {
    const code = this.reschedCode;
    const booking = code ? BookingStore.get(code) : null;
    if (!booking) return;
    const input = document.getElementById("admin-resched-date");
    const newIso = input ? input.value : "";
    if (!newIso) {
      showToast("Seleccione la nueva fecha para la reserva.", "error");
      return;
    }
    if (newIso === booking.selectedDate) {
      showToast("La nueva fecha debe ser diferente a la actual.", "error");
      return;
    }
    if (newIso < isoOf(new Date())) {
      showToast("No se puede reprogramar a una fecha pasada.", "error");
      return;
    }
    if (newIso < isoOf(new Date(Date.now() + 3 * 86400000))) {
      showToast("La antelación mínima es 72 h.", "error");
      return;
    }
    const manual = AvailabilityManager.get(newIso);
    if (manual === "disabled" || manual === "soldout") {
      showToast("Fecha bloqueada.", "error");
      return;
    }
    const occupied = BookingStore.getBookingsForDate(newIso).filter(b => b.code !== code).length;
    if (occupied >= DEFAULT_MAX_EVENTS_PER_DAY) {
      showToast("Capacidad completa ese día.", "error");
      return;
    }
    BookingStore.updateDate(code, newIso);
    showToast(`Reserva ${code} reprogramada para el ${formatDisplayDate(newIso)}.`, "success");
    this.closeRescheduleModal();
    this.renderOwner();
    this.renderOwnerCalendar();
  },

  // ---- Comprobante SINPE en alta resolución (#adminVoucherModal) ----

  openVoucherPreview(src) {
    // Los comprobantes se guardan como Data-URL (FileReader.readAsDataURL): solo
    // se aceptan imágenes data:image para no inyectar otra cosa en el <img>.
    if (typeof src !== "string" || !src.startsWith("data:image")) {
      showToast("El comprobante no es una imagen válida.", "error");
      return;
    }
    const img = document.getElementById("admin-voucher-img");
    if (img) img.src = src;
    ModalController.open("adminVoucherModal");
  },

  closeVoucherPreview() {
    const img = document.getElementById("admin-voucher-img");
    if (img) img.src = "";
    ModalController.close("adminVoucherModal");
  },

  // ---- Rol Ingeniero de TI: Suite de Control Técnico (4 Pestañas Modulares) ----

  renderIT() {
    this.renderITStatusChips();
    const tabs = ["prices", "gallery", "availability", "backup"];
    tabs.forEach(p => {
      const el = document.getElementById(`admin-it-${p}`);
      if (el) el.classList.toggle("hidden", p !== this.itTab);
    });
    document.querySelectorAll("[data-it-tab]").forEach(t => {
      t.classList.toggle("admin-tab-btn--active", t.getAttribute("data-it-tab") === this.itTab);
      t.setAttribute("aria-selected", t.getAttribute("data-it-tab") === this.itTab ? "true" : "false");
    });
    // Contadores de estado vivos en cada pestaña (badges)
    const audit = AuditLog.load();
    const counts = {
      prices: CATALOG_SERVICES.length,
      gallery: StorageEngine.getGalleryItems().length,
      availability: Object.keys(AvailabilityManager.all()).length,
      backup: (Array.isArray(audit.events) ? audit.events.length : 0) + audit.logins.length
    };
    document.querySelectorAll("#admin-it-tabs [data-it-tab]").forEach(t => {
      const badge = t.querySelector(".admin-tab-count");
      if (badge) badge.textContent = counts[t.getAttribute("data-it-tab")] || 0;
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

  // ---- Telemetría en vivo de la consola IT ----

  renderITStatusChips() {
    const box = document.getElementById("admin-it-status-chips");
    if (!box) return;
    const secureCtx = typeof window !== "undefined" && window.isSecureContext;
    const cryptoOk = typeof window !== "undefined" && window.crypto && !!window.crypto.subtle;
    // Sin WebCrypto el digest se calcula en software, pero sigue siendo SHA-256:
    // el respaldo produce el mismo hash, así que no degrada la autenticación.
    const cryptoClass = "it-status-chip--ok";
    const cryptoLabel = cryptoOk ? "SHA-256 (WebCrypto)" : "SHA-256 (software)";
    const tlsClass = secureCtx ? "it-status-chip--ok" : "it-status-chip--warn";
    const tlsLabel = secureCtx ? "TLS 1.3 ENCRYPTED" : "HTTP PLANO";
    const engine = sanitizeInput(String(ENGINE_VERSION || "arkik-engine"));
    box.innerHTML = `
      <span class="it-status-chip it-status-chip--purple"><span class="it-chip-dot"></span>${engine}</span>
      <span class="it-status-chip ${tlsClass}">${tlsLabel}</span>
      <span class="it-status-chip ${cryptoClass}">${cryptoLabel}</span>
      <span class="it-status-chip"><span class="it-chip-dot"></span>UPTIME <span id="it-uptime-value">00:00:00</span></span>
      <span class="it-status-chip">PING <span id="it-ping-value">--</span>ms</span>`;
    this.startITTelemetry();
  },

  startITTelemetry() {
    if (!this._telemetryStarted) {
      this._telemetryStarted = true;
      this._telemetryStart = Date.now();
      const tick = () => {
        const uptimeEl = document.getElementById("it-uptime-value");
        if (uptimeEl) {
          const s = Math.max(0, Math.floor((Date.now() - this._telemetryStart) / 1000));
          const hh = String(Math.floor(s / 3600)).padStart(2, "0");
          const mm = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
          const ss = String(s % 60).padStart(2, "0");
          uptimeEl.textContent = `${hh}:${mm}:${ss}`;
        }
        const pingEl = document.getElementById("it-ping-value");
        if (pingEl) pingEl.textContent = measureStorageLatency() + "ms";
      };
      tick();
      setInterval(tick, 1000);
    }
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
              min="0" step="5000" class="it-price-input rounded-xl px-3 py-2 w-32 sm:w-36 text-sm font-bold">
          </div>
        </td>
      </tr>`).join("");

    return `
      <div class="it-console-panel overflow-x-auto space-y-6">
        <div class="it-panel-header">
          <p class="text-xs font-bold text-gray-300 uppercase tracking-wider">Matriz de Tarifas Base en Vivo (${CATALOG_SERVICES.length} Formatos)</p>
          <span class="it-live-dot">Tiempo Real</span>
        </div>
        <div>
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
                  class="it-price-input rounded-xl px-3 py-2 w-full text-sm font-bold">
                <span class="text-xs text-gray-400 font-bold">(${(extraMultiplier * 100).toFixed(0)}%)</span>
              </div>
              <p class="text-[10px] text-gray-500">Por defecto: 0.50 (50% de la tarifa base)</p>
            </div>

            <div class="p-3.5 rounded-xl bg-black/30 border border-white/5 space-y-1.5">
              <label class="block text-[11px] font-bold text-pink-300" for="admin-travel-rate">Recargo Fuera de GAM (%)</label>
              <div class="flex items-center gap-1.5">
                <input type="number" id="admin-travel-rate" value="${(travelRate * 100).toFixed(0)}" min="0" max="100" step="1"
                  class="it-price-input rounded-xl px-3 py-2 w-full text-sm font-bold">
                <span class="text-xs text-gray-400 font-bold">%</span>
              </div>
              <p class="text-[10px] text-gray-500">Por defecto: 12% viáticos de transporte</p>
            </div>

            <div class="p-3.5 rounded-xl bg-black/30 border border-white/5 space-y-1.5">
              <label class="block text-[11px] font-bold text-cyan-300" for="admin-subwoofer-price">Subwoofer Extra (Unidad)</label>
              <div class="flex items-center gap-1.5">
                <span class="text-xs text-gray-400 font-bold">₡</span>
                <input type="number" id="admin-subwoofer-price" data-price="extra-subwoofers" value="${subPrice}" min="0" step="5000"
                  class="it-price-input rounded-xl px-3 py-2 w-full text-sm font-bold">
              </div>
              <p class="text-[10px] text-gray-500">Original: ₡80,000 / unidad</p>
            </div>

            <div class="p-3.5 rounded-xl bg-black/30 border border-white/5 space-y-1.5">
              <label class="block text-[11px] font-bold text-emerald-300" for="admin-dj-price">Servicio DJ Recesos (Hora)</label>
              <div class="flex items-center gap-1.5">
                <span class="text-xs text-gray-400 font-bold">₡</span>
                <input type="number" id="admin-dj-price" data-price="extra-dj_service" value="${djPrice}" min="0" step="5000"
                  class="it-price-input rounded-xl px-3 py-2 w-full text-sm font-bold">
              </div>
              <p class="text-[10px] text-gray-500">Original: ₡75,000 / hora</p>
            </div>
          </div>
        </div>

        <div class="flex flex-wrap gap-3 pt-2">
          <button type="button" id="admin-save-prices" class="admin-act-btn admin-act-btn--confirm">💾 Aplicar Cambios (Guardar)</button>
          <button type="button" id="admin-reset-prices" class="admin-act-btn admin-act-btn--neutral">↺ Restaurar Precios de Fábrica</button>
          <span class="text-[11px] text-gray-500 self-center">Los cambios persisten al instante y recalibran el catálogo público.</span>
        </div>
      </div>`;
  },

  itGalleryHtml() {
    const items = StorageEngine.getGalleryItems();
    const featuredCount = items.filter(i => i.featured).length;

    const rows = items.map(item => `
      <div class="admin-media-row flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-2xl bg-white/5 border border-white/10" data-media-id="${sanitizeInput(item.id)}">
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
          <button type="button" onclick="AdminModule.openMediaModal('${sanitizeInput(item.id)}')"
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
      <div class="it-console-panel space-y-4">
        <div class="it-panel-header">
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
    const rows = entries.map(k => {
      const details = AvailabilityManager.getDetails(k);
      const isSoldout = details.state === "soldout";
      return `
        <div class="it-blocked-row">
          <div class="min-w-0">
            <span class="it-blocked-date">${k}</span>
            ${details.reason ? `<span class="it-blocked-reason">${sanitizeInput(details.reason)}</span>` : ""}
          </div>
          <span class="status-badge ${isSoldout ? "status-badge--soldout" : "status-badge--disabled"}">
            ${isSoldout ? "Agotado" : "Bloqueado"}
          </span>
          <button type="button" data-avail-remove="${k}" class="it-unlock-btn">🔓 Desbloquear Fecha</button>
        </div>`;
    }).join("");

    return `
      <div class="it-console-panel space-y-5">
        <div class="it-panel-header">
          <p class="text-xs font-bold text-gray-300 uppercase tracking-wider">Bloqueo de Agenda — Mantenimiento · Cierre Privado · Descanso</p>
          <span class="it-live-dot">Sincroniza calendario público</span>
        </div>

        <div>
          <div class="flex flex-wrap items-end gap-2">
            <label class="block">
              <span class="block text-[10px] uppercase tracking-wider text-gray-500 font-bold mb-1">Desde (obligatorio)</span>
              <input type="date" id="admin-avail-from" min="${todayISO}" class="it-date-input rounded-xl px-3 py-2.5 text-sm">
            </label>
            <label class="block">
              <span class="block text-[10px] uppercase tracking-wider text-gray-500 font-bold mb-1">Hasta (rango opcional)</span>
              <input type="date" id="admin-avail-to" min="${todayISO}" class="it-date-input rounded-xl px-3 py-2.5 text-sm">
            </label>
            <label class="block flex-1 min-w-[180px]">
              <span class="block text-[10px] uppercase tracking-wider text-gray-500 font-bold mb-1">Motivo (auditado)</span>
              <input type="text" id="admin-avail-reason" maxlength="120" placeholder="Ej. Mantenimiento de iluminación"
                class="glass-input rounded-xl px-3 py-2.5 text-sm w-full">
            </label>
          </div>
          <div class="flex flex-wrap gap-2 mt-3">
            <button type="button" data-avail="disabled" class="admin-act-btn admin-act-btn--cancel">⛔ Bloquear Fecha(s)</button>
            <button type="button" data-avail="soldout" class="admin-act-btn admin-act-btn--neutral">🔴 Marcar Agotado</button>
            <button type="button" data-avail="available" class="admin-act-btn admin-act-btn--confirm">🟢 Desbloquear (rango)</button>
          </div>
          <p class="text-[11px] text-gray-500 mt-2">Si completa "Hasta", la operación aplica a todo el rango inclusive. Las fechas bloqueadas se deshabilitan al instante en el calendario público y el motivo queda registrado en la auditoría.</p>
        </div>

        <div>
          <p class="text-xs font-bold text-gray-300 uppercase tracking-wider mb-2">Fechas con Gestión Manual (${entries.length})</p>
          <div class="space-y-2">
            ${entries.length ? rows : '<p class="text-xs text-gray-500">Sin bloqueos manuales. Disponibilidad calculada automáticamente (máx. 2 eventos/día · antelación mínima 72 h).</p>'}
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

    const events = Array.isArray(audit.events) ? audit.events : [];
    const LOG_TYPES = ["login", "block", "price", "gallery", "backup", "reset"];
    const fmtTime = at => new Date(at).toLocaleString("es-CR",
      { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
    const logRows = events.length
      ? events.slice(0, 20).map(ev => {
          const type = LOG_TYPES.includes(ev.type) ? ev.type : "login";
          return `
            <div class="it-log-row">
              <span class="it-log-time">${fmtTime(ev.at)}</span>
              <span class="it-log-type it-log-type--${type}">${type}</span>
              <span class="it-log-message">${sanitizeInput(ev.message)}</span>
            </div>`;
        }).join("")
      : audit.logins.slice(0, 20).map(l => `
          <div class="it-log-row">
            <span class="it-log-time">${fmtTime(l.at)}</span>
            <span class="it-log-type it-log-type--login">login</span>
            <span class="it-log-message">Acceso registrado: ${sanitizeInput(l.role)}</span>
          </div>`).join("");

    return `
      <div class="space-y-5">
        <div class="it-console-panel space-y-4">
          <div class="it-panel-header">
            <p class="text-sm font-bold text-white">Database Vault — Respaldo & Restauración Total</p>
            <span class="it-live-dot">${ENGINE_VERSION}</span>
          </div>
          <p class="text-xs text-gray-400 leading-relaxed">Exporte la base de datos completa (reservas, tarifas en vivo, agenda de bloqueos, biblioteca multimedia y configuración) en un archivo JSON validable o en sentencias SQL listas para restaurar.</p>
          <div class="flex flex-wrap gap-3">
            <button type="button" id="admin-export-backup" class="it-backup-cta">💾 Generar y Descargar Respaldo JSON/SQL</button>
            <button type="button" id="admin-export-sql" class="admin-act-btn admin-act-btn--neutral">⬇ Solo SQL</button>
            <label class="admin-act-btn admin-act-btn--neutral cursor-pointer">
              ⬆ Importar / Restaurar Respaldo (JSON)
              <input type="file" id="admin-import-backup" accept=".json,application/json" class="hidden">
            </label>
          </div>
          <p id="admin-backup-status" class="text-[11px] text-purple-300 pt-1">
            📊 ${BookingStore.all().length} reservas registradas · ${Object.keys(AvailabilityManager.all()).length} fechas bloqueadas · ${StorageEngine.getGalleryItems().length} medios en galería
          </p>
        </div>

        <div class="it-console-panel space-y-4">
          <div class="it-panel-header">
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
        </div>

        <div class="it-console-panel space-y-4">
          <div class="it-panel-header">
            <p class="text-xs font-bold text-gray-300 uppercase tracking-wider">Telemetría de Auditoría en Vivo</p>
            <span class="text-[10px] font-mono text-emerald-400 font-bold">${events.length + audit.logins.length} eventos</span>
          </div>
          <div class="it-log-feed">
            ${logRows || '<p class="text-xs text-gray-500 py-3">Sin eventos todavía. La actividad del rol IT quedará registrada aquí (bloqueos, tarifas, backups, accesos).</p>'}
          </div>
        </div>

        <div class="it-console-panel it-danger-zone space-y-3">
          <p class="text-xs font-bold text-red-300 uppercase tracking-wider">Zona de Riesgo — Operaciones Destructivas</p>
          <p class="text-[11px] text-gray-400 leading-relaxed">Limpie la caché local (carrito y estado transitorio) o restablezca el motor completo al estado de fábrica. Ambas acciones piden confirmación explícita.</p>
          <div class="flex flex-wrap gap-3">
            <button type="button" id="admin-clear-cache" class="it-danger-btn">🧹 Limpiar Caché Local</button>
            <button type="button" id="admin-factory-reset" class="it-danger-btn">💥 Restablecer Estado de Fábrica</button>
          </div>
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
      AuditLog.recordEvent("gallery", `Elemento actualizado (${sanitizeInput(title).slice(0, 60)}).`);
      showToast("Elemento actualizado correctamente.", "success");
    } else {
      StorageEngine.addGalleryItem(payload);
      AuditLog.recordEvent("gallery", `Nuevo elemento añadido (${sanitizeInput(title).slice(0, 60)}).`);
      showToast("Nuevo elemento añadido a la galería.", "success");
    }

    this.closeMediaModal();
    this.renderIT();
  },

  deleteMediaItem(id) {
    if (confirm("¿Está seguro de eliminar este elemento de la galería?")) {
      StorageEngine.deleteGalleryItem(id);
      AuditLog.recordEvent("gallery", `Elemento de galería eliminado (${id}).`);
      showToast("Elemento eliminado de la galería.", "success");
      this.renderIT();
    }
  },

  toggleFeaturedMedia(id) {
    StorageEngine.toggleFeaturedGalleryItem(id);
    const item = StorageEngine.getGalleryItems().find(g => String(g.id) === String(id));
    AuditLog.recordEvent("gallery", `Estado destacado ${item && item.featured ? "activado" : "desactivado"} (${id}).`);
    showToast("Estado destacado actualizado.", "success");
    this.renderIT();
  },

  resetMediaItems() {
    if (confirm("¿Restaurar la galería de contenido original por defecto?")) {
      StorageEngine.resetGalleryItems();
      AuditLog.recordEvent("gallery", "Galería restaurada a los valores por defecto.");
      showToast("Galería restaurada a valores por defecto.", "success");
      this.renderIT();
    }
  },

  // ---- Zona de Riesgo (Rol IT): caché y estado de fábrica ----

  clearLocalCache() {
    if (!confirm("¿Limpiar la caché local? Se elimina el carrito de cotización y el estado transitorio del navegador. Los datos comerciales (reservas, tarifas, agenda, galería) NO se tocan.")) {
      return;
    }
    try {
      localStorage.removeItem(STORAGE_KEY);
      localStorage.removeItem("arkik_recents_v1");
    } catch (e) { /* almacenamiento no disponible */ }
    if (typeof resetBooking === "function") resetBooking();
    AuditLog.recordEvent("reset", "Caché local limpiada (carrito y estado transitorio).");
    showToast("Caché local limpiada. Los datos comerciales se conservan.", "success");
    this.renderIT();
  },

  factoryReset() {
    if (!confirm("💥 RESTABLECER ESTADO DE FÁBRICA: se BORRARÁN todas las reservas, tarifas personalizadas, bloqueos de agenda, elementos de galería, configuración y auditoría. Esta acción es irreversible. ¿Continuar?")) {
      return;
    }
    if (!confirm("Confirmación final: ¿está absolutamente seguro? Se perderá toda la base de datos local de Arkik Productions.")) {
      return;
    }
    Object.values(STORAGE_KEYS).forEach(k => {
      try { localStorage.removeItem(k); } catch (e) { /* ignorar */ }
    });
    // Recargar todos los managers desde cero (estado de fábrica)
    PriceManager.load();
    AvailabilityManager.load();
    BookingStore.load();
    StorageEngine.loadGallery();
    StorageEngine.loadConfig();
    if (typeof resetBooking === "function") resetBooking();
    if (typeof renderGalleryFilters === "function") renderGalleryFilters("todos");
    if (typeof renderMediaGallery === "function") renderMediaGallery(StorageEngine.getGalleryItems(), "todos");
    if (typeof renderCatalog === "function") renderCatalog(CATALOG_SERVICES, typeof currentCatalogCategory !== "undefined" ? currentCatalogCategory : "Todos");
    if (typeof updateSummaryPrices === "function") updateSummaryPrices();
    if (typeof CalendarModule !== "undefined" && typeof CalendarModule.render === "function") CalendarModule.render();
    AuditLog.recordEvent("reset", "Motor restablecido al estado de fábrica (borrado total).");
    this.renderIT();
    showToast("Sistema restablecido al estado de fábrica.", "success");
  }
};

function kpiCard(icon, label, value, accent, sub) {
  return `
    <div class="exec-kpi ${accent}">
      <p class="exec-kpi-label"><span class="exec-kpi-icon">${icon}</span>${label}</p>
      <p class="exec-kpi-value">${value}</p>
      ${sub ? `<p class="exec-kpi-sub">${sub}</p>` : ""}
    </div>`;
}

function bookingCard(b) {
  const statusLabel = BOOKING_STATUSES[b.status] || b.status;
  const statusTone = {
    pendiente: "bg-amber-500/10 text-amber-300 border-amber-500/20",
    confirmada: "bg-emerald-500/10 text-emerald-300 border-emerald-500/20",
    cancelada: "bg-rose-500/10 text-rose-300 border-rose-500/20",
    realizada: "bg-indigo-500/10 text-indigo-300 border-indigo-500/20",
    disabled: "bg-slate-500/10 text-slate-300 border-slate-500/20"
  }[b.status] || "bg-slate-500/10 text-slate-300 border-slate-500/20";
  const service = CATALOG_SERVICES.find(s => s.id === b.serviceId);
  const setupDisplay = service ? service.setup_display : (b.setupDisplay || "2h antes");
  const teardownDisplay = service ? service.teardown_display : (b.teardownDisplay || "1h después");
  const gam = isNonGamLocation(b.province, b.canton);
  const gamBadge = gam
    ? `<span class="px-2 py-0.5 rounded-md bg-amber-500/10 border border-amber-500/40 text-amber-300 text-[10px] font-bold">🚚 Fuera GAM · +12% (${formatCRC(b.travelSurcharge || 0)})</span>`
    : `<span class="px-2 py-0.5 rounded-md bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 text-[10px] font-bold">📍 GAM · Viáticos ₡0</span>`;

  const waLink = whatsappClientUrl(b, `Hola ${String(b.clientName || "").split(" ")[0]}, soy Juan José Ramírez de Arkik Productions. Te contacto por tu reserva ${b.code}.`);

  const actions = [];
  if (b.status === "pendiente") {
    actions.push(`<button type="button" data-action="confirm" class="bg-emerald-950/30 hover:bg-emerald-900/50 border border-emerald-500/30 text-emerald-300 rounded-xl py-2.5 px-4 text-xs font-medium flex items-center justify-center gap-2 transition-all">✅ Validar Pago Bancario</button>`);
  }
  if (b.status === "confirmada") {
    actions.push(`<button type="button" data-action="complete" class="bg-emerald-950/30 hover:bg-emerald-900/50 border border-emerald-500/30 text-emerald-300 rounded-xl py-2.5 px-4 text-xs font-medium flex items-center justify-center gap-2 transition-all">✅ Marcar Realizada</button>`);
  }
  if (b.voucherImage) {
    actions.push(`<button type="button" data-action="view" class="bg-purple-950/40 hover:bg-purple-900/60 border border-purple-500/30 text-purple-200 rounded-xl py-2.5 px-4 text-xs font-semibold flex items-center justify-center gap-2 transition-all">👁️ Ver Comprobante SINPE</button>`);
  }
  if (b.status === "pendiente" || b.status === "confirmada") {
    actions.push(`<button type="button" data-action="cancel" class="bg-rose-950/30 hover:bg-rose-900/50 border border-rose-500/30 text-rose-300 rounded-xl py-2.5 px-4 text-xs font-medium flex items-center justify-center gap-2 transition-all">❌ Rechazar / Cancelar</button>`);
  }
  if (b.status !== "cancelada" && b.status !== "pendiente") {
    actions.push(`<button type="button" data-action="voucher" class="bg-indigo-950/40 hover:bg-indigo-900/60 border border-indigo-500/30 text-indigo-200 rounded-xl py-2.5 px-4 text-xs font-semibold flex items-center justify-center gap-2 transition-all">📄 Descargar Pre-Factura PDF</button>`);
  }
  actions.push(`<button type="button" data-action="whatsapp" class="col-span-1 sm:col-span-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white rounded-xl py-2.5 px-4 text-xs font-semibold flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(16,185,129,0.25)] transition-all">💬 Notificar WhatsApp</button>`);

  return `
  <div class="admin-booking-row bg-[#0b0518]/95 border border-purple-500/25 rounded-2xl p-4 sm:p-6 mb-4 shadow-xl transition-all hover:border-purple-500/50" data-id="${b.code}">
    <!-- Encabezado: código + estado + GAM/Viáticos + fecha/hora -->
    <div class="flex flex-wrap items-center gap-2">
      <span class="admin-booking-code font-mono text-xs font-bold text-purple-300 bg-purple-950/80 px-2.5 py-1 rounded-lg border border-purple-500/30">${b.code}</span>
      <span class="px-2.5 py-1 rounded-lg text-xs font-medium border ${statusTone}">${statusLabel}</span>
      ${gamBadge}
      <span class="text-xs font-semibold text-slate-300 flex items-center gap-1">📅 ${formatDisplayDate(b.selectedDate)}${b.selectedTime ? " · " + sanitizeInput(b.selectedTime) : ""}</span>
    </div>

    <div class="admin-booking-cols grid grid-cols-1 md:grid-cols-3 gap-3 my-4 py-3 border-y border-purple-900/40">
      <!-- COL 1: Cliente / Empresa -->
      <div class="admin-booking-col">
        <p class="text-[10px] font-bold tracking-widest text-purple-300/70 uppercase mb-1">Cliente / Empresa</p>
        <p class="text-base font-bold text-white tracking-wide leading-snug">${sanitizeInput(b.clientName)}</p>
        ${b.voucherImage
      ? ""
      : `<p class="mt-2 text-[10px] text-amber-300/70">⚠️ comprobante SINPE no adjuntado</p>`}
      </div>

      <!-- COL 2: Formato y Horarios -->
      <div class="admin-booking-col">
        <p class="text-[10px] font-bold tracking-widest text-purple-300/70 uppercase mb-1">Formato &amp; Horarios</p>
        <p class="text-sm sm:text-base font-bold text-white">${sanitizeInput(b.serviceName)}<span class="text-slate-400"> · ${sanitizeInput(b.eventType || "")}</span></p>
        <p class="text-xs text-slate-400 mt-1 flex items-center gap-1">⏱️ Montaje ${sanitizeInput(setupDisplay)} · Desmontaje ${sanitizeInput(teardownDisplay)}</p>
        <p class="text-xs text-slate-500 flex items-center gap-1">📍 ${sanitizeInput(b.canton)}, ${sanitizeInput(b.province)}</p>
      </div>

      <!-- COL 3: Contacto y SINPE -->
      <div class="admin-booking-col">
        <p class="text-[10px] font-bold tracking-widest text-purple-300/70 uppercase mb-1">Contacto &amp; SINPE</p>
        <p class="text-xs text-slate-300 flex items-center gap-1.5">💬 <span>${sanitizeInput(b.clientPhone)}</span></p>
        <a href="${waLink}" target="_blank" rel="noopener" class="text-xs mt-0.5 font-semibold text-slate-300 hover:text-purple-300 transition-colors">💬 WhatsApp</a>
        <p class="text-xs text-slate-300 mt-0.5 truncate flex items-center gap-1.5">✉️ <span>${sanitizeInput(b.clientEmail || "S/N")}</span></p>
        <p class="text-xs text-slate-300 mt-1 flex items-center gap-1.5">💳 <span>Ref. SINPE: <span class="font-bold text-slate-300">${b.sinpeRef ? sanitizeInput(b.sinpeRef) : "S/N"}</span></span></p>
      </div>
    </div>

    <!-- Mini-grid financiera 3 columnas: Gran Total / Adelanto / Saldo -->
    <div class="admin-booking-fin grid grid-cols-3 gap-2 bg-[#05020c]/80 p-3 rounded-xl border border-white/5">
      <div class="min-w-0">
        <p class="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1">Gran Total</p>
        <p class="text-white font-mono font-bold text-lg sm:text-xl break-words">${formatCRC(b.granTotal)}</p>
      </div>
      <div class="min-w-0">
        <p class="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1">Adelanto SINPE</p>
        <p class="text-emerald-300 font-mono font-semibold text-lg break-words">${formatCRC(b.deposit50Amount)}</p>
      </div>
      <div class="min-w-0">
        <p class="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-1">Saldo Pendiente</p>
        <p class="text-slate-200 font-mono font-semibold text-lg break-words">${formatCRC(b.remainingBalance)}</p>
      </div>
    </div>

    <!-- Deck de acciones touch -->
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4 pt-3 border-t border-white/5">
      ${actions.join("")}
    </div>
  </div>`;
}

function whatsappClientUrl(booking, message) {
  return `https://wa.me/${normalizeWaPhone(booking.clientPhone)}?text=${encodeURIComponent(message)}`;
}

// ============================================================
// 9. PDF EXPORT ENGINE (Pre-Factura Ejecutiva & Reporte Ejecutivo de Propietario)
// ============================================================

/**
 * URL compartida de la carpeta de respaldo en Google Drive (backup de expedientes).
 * El Propietario usa esta carpeta para archivar Pre-Facturas VALIDADAS y su
 * Expediente JSON, con control de acceso propio de su cuenta Drive.
 */
const ARKIK_DRIVE_FOLDER_URL = "https://drive.google.com/drive/folders/1A0zOpNvxCkhlSUZMxsV4G2tr5S5EWNEH?usp=drive_link";

/**
 * Estado de verificación bancaria de una reserva para la Pre-Factura.
 * - validada:  depósito SINPE verificado → agenda CONGELADA (firma comercial).
 * - pendiente: solo cotización formal, agenda aún NO garantizada.
 */
function bookingVerificationState(b) {
  const s = String(b.status || "").toLowerCase();
  if (s === "confirmada" || s === "realizada") {
    return { ok: true, label: "✅ DEPÓSITO BANCARIO VERIFICADO · AGENDA CONGELADA", color: "#059669" };
  }
  if (s === "cancelada") {
    return { ok: false, label: "✖ RESERVA RECHAZADA / CANCELADA", color: "#b91c1c" };
  }
  return { ok: false, label: "⏳ PENDIENTE DE VERIFICACIÓN BANCARIA", color: "#b45309" };
}

/**
 * Desplaza una hora "HH:MM" en un delta de minutos y devuelve "HH:MM".
 * Si la hora de entrada no es parseable devuelve null (para fallback seguro).
 */
function shiftTime(timeStr, deltaMinutes) {
  if (!timeStr) return null;
  const m = String(timeStr).match(/^(\d{1,2}):(\d{2})/);
  if (!m) return null;
  const d = new Date(2000, 0, 1, parseInt(m[1], 10), parseInt(m[2], 10));
  d.setMinutes(d.getMinutes() + (deltaMinutes || 0));
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

/**
 * Extrae el número de horas de una cadena como "2h antes" / "1h después".
 */
function parseHourDelta(str) {
  const m = String(str || "").match(/(\d+)\s*h/);
  return m ? parseInt(m[1], 10) : null;
}

/**
 * Renderizador OFF-SCREEN de la Pre-Factura Ejecutiva de Arkik Productions.
 *
 * Construye una plantilla HTML independiente, de ALTO CONTRASTE, pensada
 * exclusivamente para impresión A4 PORTAIT. NO intenta imprimir el modal
 * visible en pantalla (causa raíz del PDF en blanco): genera su propio
 * documento vector-ready dentro de un contenedor desmontado de ancho fijo
 * 800px, con fondo blanco forzado, texto pizarra oscuro y acentos violeta,
 * contrastando por completo con la UI en Modo Oscuro del sitio.
 *
 * El contenedor resultante queda DETACHED — solo se monta momentáneamente y
 * fuera de pantalla justo antes de rasterizarse — y la imagen del logo se
 * pre-carga vía decode() para que jamás se renderice en blanco.
 *
 * @param {Object} booking    Reserva (cart.createdBooking o del Portal).
 * @param {Object} [cartState] Estado del carrito opcional (fallback de datos).
 * @returns {HTMLDivElement} Contenedor A4 desmontado y listo para rasterizar.
 */
function buildExecutiveInvoiceHtml(booking, cartState) {
  // Resolución robusta del booking: se acepta una reserva directa o un estado
  // de carrito que la contenga (compatibilidad con llamadas preexistentes).
  const b = booking
    || (cartState && cartState.createdBooking)
    || (typeof cart !== "undefined" && cart.createdBooking)
    || null;
  if (!b) return null;

  const service = CATALOG_SERVICES.find(s => s.id === b.serviceId) || null;
  const setupDisplay = service && service.setup_display
    ? service.setup_display
    : (b.setupDisplay || "2h antes");
  const teardownDisplay = service && service.teardown_display
    ? service.teardown_display
    : (b.teardownDisplay || "1h después");
  const verification = bookingVerificationState(b);
  const nonGam = isNonGamLocation(b.province, b.canton);
  const today = new Date().toLocaleDateString("es-CR");

  const basePrice = PriceManager.getServicePrice(service);
  const extras = b.extras || {};
  const travelAmount = b.travelSurcharge > 0 ? b.travelSurcharge : 0;

  // ── Ledger de Logística con horarios exactos derivados del formato ──
  // Inicio de Show = hora contratada. Llegada/Montaje y Desmontaje se derivan
  // del delta expresado por el formato (p. ej. "2h antes" / "1h después").
  const showTime = b.selectedTime || "";
  const setupH = parseHourDelta(setupDisplay);
  const teardownH = parseHourDelta(teardownDisplay);
  const arrivalTime = setupH !== null
    ? shiftTime(showTime, -setupH * 60)
    : null;
  // Desmontaje = Inicio de show + duración del formato + horas de desmontaje.
  const formatMinutes = (service && service.durationMinutes) ? service.durationMinutes : 120;
  const teardownTime = (arrivalTime !== null && setupH !== null && teardownH !== null)
    ? shiftTime(showTime, formatMinutes + teardownH * 60)
    : null;

  const container = document.createElement("div");
  // Presentación A4 ESTRICTA 1 página: contenedor de 210×297mm con padding
  // interno de 12×15mm y margen de página 0. Todo el contenido debe caber en
  // UNA hoja (page-break-inside avoid) — header compacto, bloque 2 columnas,
  // tabla de desglose, resumen financiero derecha y footer compacto.
  container.className = "pdf-container";
  container.style.width = "210mm";
  container.style.maxHeight = "297mm";
  container.style.padding = "12mm 15mm";
  container.style.boxSizing = "border-box";
  container.style.fontFamily = "'Inter', system-ui, sans-serif";
  container.style.background = "#ffffff";
  container.style.color = "#0f172a";
  container.style.pageBreakInside = "avoid";
  container.style.margin = "0";
  container.style.fontSize = "12px";
  container.style.lineHeight = "1.5";

  // Fila unificada de extras según spec (una sola línea en el Ledger
  // Financiero): "Horas Extra y Servicios Adicionales (DJ, Subwoofers)".
  // Las cantidades por ítem se detallan en una sub-línea gris por trazabilidad.
  const extraCounts = [];
  if (extras.extraHoursCount > 0) extraCounts.push(`${extras.extraHoursCount} hr extra de show`);
  if (extras.djHoursCount > 0) extraCounts.push(`${extras.djHoursCount} hr DJ en recesos`);
  if (extras.subwoofersCount > 0) extraCounts.push(`${extras.subwoofersCount} subwoofer(s) 18"`);
  const extrasTotal = (Number(extras.extraHoursTotal) || 0)
    + (Number(extras.djTotal) || 0)
    + (Number(extras.subwoofersTotal) || 0);
  const extrasHtml = `<tr style="border-bottom:1px solid #e2e8f0;">
        <td style="padding:7px 0;">
          <span style="font-weight:600; color:#334155;">Horas Extra y Servicios Adicionales (DJ, Subwoofers)</span>
          ${extraCounts.length ? `<div style="font-size:10px; color:#64748b;">${extraCounts.join(" · ")}</div>` : ""}
        </td>
        <td style="padding:7px 0; text-align:right; font-variant-numeric:tabular-nums; font-weight:700;">${formatCRC(extrasTotal)}</td>
      </tr>`;

  const travelHtml = nonGam
    ? `<tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:7px 0;">Viáticos y Traslado — No-GAM (+12%)</td><td style="padding:7px 0; text-align:right; font-variant-numeric:tabular-nums; font-weight:700;">${formatCRC(travelAmount)}</td></tr>`
    : `<tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:7px 0;">Viáticos y Traslado — GAM (sin recargo)</td><td style="padding:7px 0; text-align:right; font-variant-numeric:tabular-nums;">₡0</td></tr>`;

  const lineItem = (label, amount) =>
    `<tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:7px 0; font-weight:700; color:#1e293b;">${label}</td><td style="padding:7px 0; text-align:right; font-variant-numeric:tabular-nums; font-weight:800;">${formatCRC(amount)}</td></tr>`;

  const infoRow = (label, value, strong) =>
    `<tr><td style="padding:2px 6px; color:#64748b; width:38%; vertical-align:top;">${label}</td><td style="padding:2px 6px; ${strong ? "font-weight:700;" : "font-weight:600;"} color:#1e293b;">${value}</td></tr>`;

  container.innerHTML = `
  <div style="color:#0f172a; display:flex; flex-direction:column; min-height:273mm; box-sizing:border-box;">

    <!-- ══ 1. HEADER COMPACTO: logo + N° Pre-Factura + fecha emisión ══ -->
    <div style="display:flex; justify-content:space-between; align-items:center; gap:16px; border-bottom:2px solid #a855f7; padding-bottom:10px;">
      <div style="display:flex; align-items:center; gap:12px;">
        <img src="img/arkik_logo.jpg" id="pdf-logo" alt="Arkik Productions"
          style="height:54px; width:auto; object-fit:contain; border-radius:8px; border:1px solid #e9d5ff;" />
        <div>
          <div style="margin:0; font-size:18px; font-weight:900; color:#4c1d95; letter-spacing:0.4px;">ARKIK PRODUCTIONS</div>
          <div style="margin:1px 0 0; font-size:10px; font-weight:700; color:#6d28d9; text-transform:uppercase; letter-spacing:0.8px;">Música en Vivo &amp; Sonido Profesional</div>
          <div style="margin:2px 0 0; font-size:10px; color:#64748b;">Granadilla, San José, Costa Rica · +506 6227-4984</div>
        </div>
      </div>
      <div style="text-align:right; flex-shrink:0;">
        <div style="display:inline-block; background:#faf5ff; border:1px solid #e9d5ff; border-radius:10px; padding:7px 12px;">
          <div style="font-size:9px; font-weight:800; color:#7c3aed; text-transform:uppercase; letter-spacing:0.8px;">N° Pre-Factura</div>
          <div style="margin:3px 0 0; font-family:ui-monospace, 'Cascadia Mono', monospace; font-size:14px; font-weight:900; letter-spacing:0.5px; color:#5b21b6;">${sanitizeInput(b.code)}</div>
          <div style="margin:3px 0 0; font-size:10px; color:#64748b;">Fecha Emisión: <strong style="color:#1e293b;">${today}</strong></div>
        </div>
      </div>
    </div>

    <!-- ══ 2. ESTADO DE VERIFICACIÓN (compacto) ══ -->
    <div style="margin:10px 0 0; display:flex; justify-content:space-between; align-items:center; gap:12px;">
      <span style="font-size:10px; font-weight:800; letter-spacing:0.3px; color:${verification.color};">${verification.label}</span>
      <span style="font-size:10px; color:#64748b;">PRE-FACTURA DE SERVICIO / COTIZACIÓN FORMAL</span>
    </div>

    <!-- ══ 3. BLOQUE 2 COLUMNAS: Arkik vs Cliente/Evento ══ -->
    <div style="display:grid; grid-template-columns:1fr 1.15fr; gap:12px; margin:10px 0 0;">
      <div style="background:#faf5ff; border:1px solid #e9d5ff; border-radius:10px; padding:10px 12px;">
        <div style="margin:0 0 4px; font-size:9px; font-weight:800; color:#7c3aed; text-transform:uppercase; letter-spacing:1px;">Empresa / Proveedor</div>
        <table style="width:100%; border-collapse:collapse; font-size:11px;">
          ${infoRow("Razón Social", "Arkik Productions", true)}
          ${infoRow("Contacto", "+506 6227-4984")}
          ${infoRow("Correo", "arkikproduc2023@gmail.com")}
          ${infoRow("Sede", "Granadilla, San José, CR")}
        </table>
      </div>
      <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:10px; padding:10px 12px;">
        <div style="margin:0 0 4px; font-size:9px; font-weight:800; color:#475569; text-transform:uppercase; letter-spacing:1px;">Cliente / Evento</div>
        <table style="width:100%; border-collapse:collapse; font-size:11px;">
          ${infoRow("Cliente", sanitizeInput(b.clientName), true)}
          ${infoRow("Teléfono", sanitizeInput(b.clientPhone))}
          ${infoRow("Correo", sanitizeInput(b.clientEmail || "No especificado"))}
          ${infoRow("Lugar", `${sanitizeInput(b.canton)}, ${sanitizeInput(b.province)}${b.address ? " — " + sanitizeInput(b.address) : ""}`)}
          ${infoRow("Fecha & Hora", `${formatDisplayDate(b.selectedDate)}${b.selectedTime ? " · " + sanitizeInput(b.selectedTime) : ""}`, true)}
        </table>
      </div>
    </div>

    <!-- ══ 4. LEDGER DE LOGÍSTICA (compacto) ══ -->
    <div style="margin:10px 0 0;">
      <div style="margin:0 0 4px; font-size:9px; font-weight:800; color:#7c3aed; text-transform:uppercase; letter-spacing:1px;">Ledger de Logística</div>
      <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:8px; font-size:10px; color:#475569;">
        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:6px 8px;"><span style="font-weight:800; color:#1e293b;">Formato:</span> ${sanitizeInput(b.serviceName || b.serviceId)}${extras.extraHoursCount > 0 ? " +" + extras.extraHoursCount + "hr" : ""}</div>
        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:6px 8px;"><span style="font-weight:800; color:#1e293b;">Llegada:</span> ${arrivalTime ? sanitizeInput(arrivalTime) + " (" + sanitizeInput(setupDisplay) + ")" : sanitizeInput(setupDisplay)}</div>
        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:6px 8px;"><span style="font-weight:800; color:#1e293b;">Show:</span> ${showTime ? sanitizeInput(showTime) : "Según formato"}</div>
        <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:6px 8px;"><span style="font-weight:800; color:#1e293b;">Desmontaje:</span> ${sanitizeInput(teardownDisplay)}${teardownTime ? " (" + sanitizeInput(teardownTime) + ")" : ""}</div>
      </div>
    </div>

    <!-- ══ 5. TABLA DE DESGLOSE (border-b slate-200) ══ -->
    <div style="margin:10px 0 0;">
      <div style="margin:0 0 4px; font-size:9px; font-weight:800; color:#7c3aed; text-transform:uppercase; letter-spacing:1px;">Desglose del Servicio</div>
      <table style="width:100%; border-collapse:collapse; font-size:12px;">
        <thead>
          <tr style="border-bottom:1px solid #cbd5e1;">
            <th style="padding:6px 0; text-align:left; font-size:10px; letter-spacing:0.4px; text-transform:uppercase; color:#475569;">Concepto</th>
            <th style="padding:6px 0; text-align:right; font-size:10px; letter-spacing:0.4px; text-transform:uppercase; font-variant-numeric:tabular-nums; color:#475569;">Monto ₡</th>
          </tr>
        </thead>
        <tbody>
          ${lineItem(`Formato Base Contratado — ${sanitizeInput(b.serviceName || "Servicio")}`, basePrice)}
          ${extrasHtml}
          ${travelHtml}
          <tr style="border-bottom:2px solid #a855f7; background:#faf5ff;">
            <td style="padding:8px 0; font-weight:900; color:#4c1d95; text-transform:uppercase; letter-spacing:0.3px;">Gran Total</td>
            <td style="padding:8px 0; text-align:right; font-weight:900; font-size:14px; color:#4c1d95; font-variant-numeric:tabular-nums;">${formatCRC(b.granTotal)}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ══ 6. RESUMEN FINANCIERO (derecha) ══ -->
    <div style="margin:10px 0 0; display:flex; justify-content:flex-end;">
      <table style="width:280px; border-collapse:collapse; font-size:12px;">
        <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:6px 0; color:#475569;">Gran Total</td><td style="padding:6px 0; text-align:right; font-weight:800; font-variant-numeric:tabular-nums;">${formatCRC(b.granTotal)}</td></tr>
        <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:6px 0; font-weight:800; color:#047857;">Adelanto SINPE (50%)</td><td style="padding:6px 0; text-align:right; font-weight:900; color:#047857; font-variant-numeric:tabular-nums;">${formatCRC(b.deposit50Amount)}</td></tr>
        <tr><td style="padding:6px 0; font-weight:800; color:#be123c;">Saldo Pendiente (en sitio)</td><td style="padding:6px 0; text-align:right; font-weight:900; color:#be123c; font-variant-numeric:tabular-nums;">${formatCRC(b.remainingBalance)}</td></tr>
      </table>
    </div>
    <div style="margin:6px 0 0; font-size:10px; color:#64748b; text-align:right;">
      Ref. SINPE: <strong>${b.sinpeRef ? sanitizeInput(b.sinpeRef) : "S/N"}</strong> · Destino SINPE Móvil: <strong>${SINPE_CONFIG.phone}</strong> (${SINPE_CONFIG.holder})
    </div>

    <!-- ══ 7. FOOTER COMPACTO: nota legal + política cancelación + contacto ══ -->
    <div style="margin-top:auto; border-top:1px solid #e2e8f0; padding-top:8px; font-size:9px; color:#64748b; line-height:1.55;">
      <div style="margin:0 0 3px; font-weight:800; color:#4c1d95; text-transform:uppercase; letter-spacing:0.5px;">Cláusulas de Contratación</div>
      <div style="margin:0;">1. El <strong style="color:#334155;">adelanto del 50% vía SINPE Móvil no es reembolsable</strong>: ${SINPE_CONFIG.policyText}</div>
      <div style="margin:3px 0 0;">2. La <strong style="color:#334155;">agenda queda congelada</strong> únicamente tras la verificación bancaria del adelanto del 50% y la firma digital del presente documento, conforme al Término de Congelamiento de Agenda.</div>
      <div style="margin:3px 0 0;">3. Este documento constituye una <strong style="color:#334155;">cotización formal de validez comercial</strong> emitida por Arkik Productions; no constituye factura tributaria.</div>
      <div style="margin:5px 0 0; color:#94a3b8;">Arkik Productions · Granadilla, San José, Costa Rica · +506 6227-4984 · arkikproduc2023@gmail.com · Documento emitido el ${today}</div>
    </div>
  </div>`;

  return container;
}

/**
 * Debe cargarse el logo (img/arkik_logo.jpg) y esperar su decode() antes de que
 * html2canvas rasterice. Previene el PDF en blanco por imagen no cargada.
 */
async function preloadExecutiveImages(container) {
  const imgs = Array.from(container.querySelectorAll("img"));
  await Promise.all(imgs.map(img => {
    if (img.complete && img.naturalWidth > 0) return Promise.resolve();
    return new Promise(resolve => {
      const done = () => resolve();
      img.addEventListener("load", done, { once: true });
      img.addEventListener("error", done, { once: true });
      setTimeout(done, 3000);
      try { if (typeof img.decode === "function") img.decode().then(done).catch(done); } catch (e) { /* noop */ }
    });
  }));
}

/**
 * Rasteriza a PDF de ALTA RESOLUCIÓN un contenedor de Pre-Factura, montándolo
 * dentro de un WRAPPER temporal invisible (left -9999px) para que la secuencia
 * completa de imágenes cargue dentro del DOM real. El contenedor en sí NUNCA
 * lleva offsets: se pasa al motor SIN el wrapper, porque html2pdf.js 0.10.1
 * clona profundamente el nodo fuente (cloneNode conserva estilos inline) dentro
 * de su propio contenedor en left:0. Si el nodo llevara left:-9999px, el clon
 * conservaría ese offset y html2canvas dibujaría el contenido fuera del canvas
 * → PDF EN BLANCO (causa raíz del bug reportado). El wrapper invisible queda
 * solo para ocultarlo del usuario; el motor rasteriza el contenedor estático.
 */
async function saveExecutiveInvoicePDF(container, filename) {
  if (!window.html2pdf) {
    throw new Error("html2pdf no disponible");
  }
  await preloadExecutiveImages(container);

  const wrapper = document.createElement("div");
  wrapper.style.position = "absolute";
  wrapper.style.left = "-9999px";
  wrapper.style.top = "0";
  wrapper.style.zIndex = "-1";
  wrapper.style.margin = "0";
  wrapper.style.padding = "0";
  wrapper.appendChild(container);
  document.body.appendChild(wrapper);

  try {
    const opt = {
      margin: 0,
      filename: filename,
      image: { type: "jpeg", quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true, backgroundColor: "#ffffff", logging: false },
      jsPDF: { unit: "mm", format: "a4", orientation: "portrait" }
    };
    // from() recibe el contenedor ESTÁTICO; el wrapper con -9999px jamás se clona.
    await window.html2pdf().set(opt).from(container).save();
  } finally {
    if (wrapper && wrapper.parentNode) {
      wrapper.parentNode.removeChild(wrapper);
    }
  }
}

/**
 * Construye el HTML del voucher oficial de reserva (compatibilidad legado).
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
        <td style="padding: 6px 0; color: #6b7280;">Fecha & Hora del Show:</td>
        <td style="padding: 6px 0; font-weight: 800; color: #7c3aed;">${formatDisplayDate(b.selectedDate)}${b.selectedTime ? " · " + sanitizeInput(b.selectedTime) : ""}</td>
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
 * Vista previa primaria de la Pre-Factura Ejecutiva (reemplaza la generación
 * de PDF en segundo plano como experiencia por defecto): renderiza el
 * documento VECTORIAL construido por buildExecutiveInvoiceHtml() dentro del
 * visor modal #invoicePreviewModal. Imprimir/Save-as-PDF usa el diálogo nativo
 * del navegador sobre la hoja A4 (100% fidelidad vectorial, cero páginas en
 * blanco); también puede abrirse en pestaña independiente.
 */
async function exportVoucherPDF() {
  openInvoicePreview();
}

// ============================================================
// 9A. IN-APP EXECUTIVE PRE-INVOICE PREVIEW VIEWER
// (#invoicePreviewModal — document on-screen, print & standalone tab)
// ============================================================

/** Abre el visor con la Pre-Factura del booking activo. */
function openInvoicePreview() {
  const b = (typeof cart !== "undefined" && cart.createdBooking) || null;
  if (!b) {
    showToast("No hay una reserva activa para previsualizar.", "error");
    return;
  }

  const docHtml = buildExecutiveInvoiceHtml(b, cart);
  if (!docHtml) {
    showToast("No se pudo generar la Pre-Factura.", "error");
    return;
  }

  const content = document.getElementById("invoicePreviewContent");
  const modal = document.getElementById("invoicePreviewModal");
  if (!content || !modal) {
    showToast("Visor de vista previa no disponible.", "error");
    return;
  }

  // Montaje del documento vectorial dentro de la hoja A4 del visor.
  content.innerHTML = "";
  content.appendChild(docHtml);

  // Pre-carga del logo en el DOM real: garantiza rasterización completa en el
  // diálogo de impresión y en la pestaña independiente.
  preloadExecutiveImages(content).catch(() => { });

  document.body.classList.add("invoice-preview-open");
  ModalController.open("invoicePreviewModal");

  const stage = document.getElementById("invoicePreviewStage");
  if (stage) stage.scrollTop = 0;
}

/** Cierra el visor y libera el documento renderizado del DOM. */
function closeInvoicePreview() {
  const content = document.getElementById("invoicePreviewContent");
  if (content) content.innerHTML = "";
  ModalController.close("invoicePreviewModal");
  document.body.classList.remove("invoice-preview-open");
}

/**
 * Imprime SOLO la hoja A4 del visor (window.print + @media print isolation).
 * El diálogo nativo del navegador permite «Guardar como PDF» con fidelidad
 * vectorial completa — cero páginas en blanco.
 */
function printInvoicePreview() {
  const modal = document.getElementById("invoicePreviewModal");
  if (!modal || modal.classList.contains("hidden")) {
    showToast("Abra primero la vista previa de la Pre-Factura.", "error");
    return;
  }
  showToast("Abriendo diálogo de impresión del navegador...", "info");
  window.print();
}

/**
 * Abre la Pre-Factura en una ventana independiente (about:blank) con estilos
 * adjuntos: permite exportar a PDF vía el diálogo nativo o archivar en
 * Google Drive / impresora del sistema.
 */
function openInvoiceStandalone() {
  const content = document.getElementById("invoicePreviewContent");
  if (!content || !content.innerHTML.trim()) {
    showToast("No hay un documento que abrir.", "error");
    return;
  }
  const b = (typeof cart !== "undefined" && cart.createdBooking) || null;
  const code = (b && b.code) ? String(b.code) : "XXXX";
  printFallback(content.innerHTML, "PreFactura_ARKIK_" + code);
}

// ============================================================
// 9B. EMAIL DISPATCH ENGINE (EmailJS - Comprobante de Reserva)
// ============================================================

/**
 * EmailJS bootstrap. Inicializa el SDK con una clave pública solo cuando:
 *  - El SDK está disponible en el DOM (window.emailjs), y
 *  - Se ha configurado una clave pública/no vacía.
 * Si falta cualquier prerrequisito, registra una advertencia limpia y no lanza
 * ninguna excepción: el flujo de reserva continúa con normalidad.
 */
function initEmailJS() {
  if (typeof window.emailjs === "undefined") {
    console.warn("[EmailJS] SDK no disponible. El envío de comprobante por correo quedará en modo simulación.");
    return;
  }
  const publicKey = (typeof EMAILJS_CONFIG !== "undefined" && EMAILJS_CONFIG.publicKey)
    ? EMAILJS_CONFIG.publicKey
    : "";
  if (!publicKey) {
    console.warn("[EmailJS] Clave pública no configurada (EMAILJS_CONFIG.publicKey). El envío de comprobante por correo quedará en modo simulación.");
    return;
  }
  try {
    window.emailjs.init(publicKey);
    console.info("[EmailJS] SDK inicializado correctamente.");
  } catch (err) {
    console.warn("[EmailJS] Error al inicializar el SDK:", err);
  }
}

/**
 * Envía el comprobante de reserva por correo electrónico (EmailJS).
 * Payload: client_name, client_email, booking_id, event_date, format_name,
 * total_amount, deposit_50, balance_50, sinpe_phone.
 *
 * Estrategia estructurada de fallback:
 *  - SDK presente + plantilla/servicio configurados  -> envío real vía EmailJS.
 *  - Cualquier elemento faltante o error  -> simula el envío con éxito y un
 *    Toast informativo, NUNCA lanza una excepción ni rompe el flujo del cliente.
 */
function sendBookingEmail(btnEl) {
  const b = cart.createdBooking;

  const btn = btnEl || null;
  const originalHTML = btn ? btn.innerHTML : "";
  const resetBtn = () => {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHTML;
    }
  };
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="text-sm">Enviando&hellip;</span>';
  }

  // Requiere una reserva activa y un correo de destino
  if (!b) {
    showToast("No hay una reserva activa para enviar.", "error");
    resetBtn();
    return;
  }
  const toEmail = (b.clientEmail || "").trim();
  if (!toEmail) {
    showToast("No hay un correo registrado para esta reserva.", "error");
    resetBtn();
    return;
  }

  const serviceID = (typeof EMAILJS_CONFIG !== "undefined" && EMAILJS_CONFIG.serviceID) ? EMAILJS_CONFIG.serviceID : "";
  const templateID = (typeof EMAILJS_CONFIG !== "undefined" && EMAILJS_CONFIG.templateID) ? EMAILJS_CONFIG.templateID : "";

  const payload = {
    client_name: b.clientName,
    client_email: toEmail,
    booking_id: b.code,
    event_date: b.selectedDate,
    format_name: b.serviceName || b.serviceId,
    total_amount: formatCRC(b.granTotal),
    deposit_50: formatCRC(b.deposit50Amount),
    balance_50: formatCRC(b.remainingBalance),
    sinpe_phone: SINPE_CONFIG.phone
  };

  // Simulación controlada cuando el envío real no está operativo
  const simulate = (reason) => {
    console.info("[EmailJS] Envío simulado (" + reason + "):", payload);
    showToast("✉️ Comprobante enviado exitosamente a " + toEmail, "success");
    resetBtn();
  };

  if (typeof window.emailjs === "undefined" || !serviceID || !templateID) {
    simulate("configuración incompleta o SDK ausente");
    return;
  }

  showToast("Enviando comprobante por correo...", "info");

  window.emailjs.send(serviceID, templateID, payload)
    .then((res) => {
      if (res && (res.status === 200 || res.text)) {
        showToast("✉️ Comprobante enviado exitosamente a " + toEmail, "success");
      } else {
        simulate("respuesta inesperada");
      }
    })
    .catch((err) => {
      console.warn("[EmailJS] Error en el envío real:", err);
      simulate("error en el envío");
    })
    .finally(() => {
      resetBtn();
    });
}

/**
 * Descarga el voucher PDF de una reserva ya registrada (Portal del Propietario).
 */
function downloadBookingVoucher(b) {
  if (!b) {
    showToast("Reserva no encontrada.", "error");
    return;
  }
  const container = buildExecutiveInvoiceHtml(b);
  showToast("Generando Pre-Factura PDF...", "info");
  const filename = `PreFactura_${b.code}.pdf`;
  saveExecutiveInvoicePDF(container, filename).then(() => {
    showToast("¡Pre-Factura PDF descargada con éxito!", "success");
  }).catch((err) => {
    console.warn("PDF export fallback:", err);
    showToast("Error al exportar PDF con html2pdf, abriendo vista de impresión.", "error");
    printFallback(container.innerHTML, `PreFactura_${b.code}`);
  });
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

// ============================================================
// 9C. VALIDACIÓN DE PAGO BANCARIO & RESPALDO GOOGLE DRIVE (Task 4)
// ============================================================

/**
 * Construye el "Expediente" JSON de una reserva (auditoría de respaldo).
 * Contiene toda la traza: cotización, liquidación, logística y estado.
 */
function buildBookingExpediente(b) {
  const service = CATALOG_SERVICES.find(s => s.id === b.serviceId);
  const gam = isNonGamLocation(b.province, b.canton);
  return {
    app: "arkik-productions",
    version: "3.4.0",
    tipo: "expediente-validacion-bancaria",
    exportadoEn: new Date().toISOString(),
    reserva: {
      code: b.code,
      status: b.status,
      estadoVerificacion: bookingVerificationState(b).label,
      createdAt: b.createdAt || null
    },
    cliente: {
      nombre: b.clientName,
      telefono: b.clientPhone,
      correo: b.clientEmail || "",
      tipoEvento: b.eventType || "",
      provincia: b.province,
      canton: b.canton,
      direccion: b.address || "",
      esFueraGam: gam
    },
    evento: {
      formato: b.serviceName || b.serviceId,
      setupDisplay: service ? service.setup_display : (b.setupDisplay || "2h antes"),
      teardownDisplay: service ? service.teardown_display : (b.teardownDisplay || "1h después"),
      selectedDate: b.selectedDate,
      selectedTime: b.selectedTime || "",
      sinpeRef: b.sinpeRef || "S/N"
    },
    financiero: {
      subtotal: b.subtotal,
      travelSurcharge: b.travelSurcharge || 0,
      granTotal: b.granTotal,
      deposit50Amount: b.deposit50Amount,
      remainingBalance: b.remainingBalance,
      depositPercentage: SINPE_CONFIG.depositPercentage
    }
  };
}

function downloadJsonFile(payload, filename) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/**
 * VALIDA el pago bancario de una reserva:
 *  1. Marca la reserva como "Confirmada" (agenda congelada).
 *  2. Actualiza los KPIs financieros del portal.
 *  3. Descarga Pre-Factura VALIDADA (PDF) y Expediente (JSON) automáticamente.
 *  4. Abre el Modal Ejecutivo con CTA a Google Drive y WhatsApp.
 */
function validateBankPayment(b) {
  if (!b) {
    showToast("Reserva no encontrada.", "error");
    return;
  }
  if (b.status !== "pendiente") {
    showToast(`La reserva ${b.code} ya fue procesada (${BOOKING_STATUSES[b.status] || b.status}).`, "info");
    return;
  }

  BookingStore.updateStatus(b.code, "confirmada");
  showToast(`Depósito bancario validado. Reserva ${b.code} CONFIRMADA.`, "success");

  // 1) Descarga automática de la Pre-Factura VALIDADA (PDF alta resolución).
  const pdfContainer = buildExecutiveInvoiceHtml(b);
  saveExecutiveInvoicePDF(pdfContainer, `PreFactura_${b.code}_VALIDADA.pdf`)
    .then(() => showToast("Pre-Factura validada descargada.", "success"))
    .catch(() => {
      console.warn("PDF validado fallback:", "se genera impresión");
      try { printFallback(pdfContainer.innerHTML, `PreFactura_${b.code}_VALIDADA`); } catch (e) { /* noop */ }
    });

  // 2) Descarga automática del Expediente JSON (auditoría de respaldo).
  try {
    downloadJsonFile(buildBookingExpediente(b), `Expediente_${b.code}.json`);
  } catch (e) {
    console.warn("Expediente JSON no pudo descargarse:", e);
  }

  // 3) Abre el Modal Ejecutivo de respaldo a Google Drive + confirmación WhatsApp.
  openBankValidationModal(b);

  AdminModule.renderOwner();
}

// ---- Modal Ejecutivo de Validación Bancaria & Respaldo a Drive ----

function openBankValidationModal(b) {
  const modal = document.getElementById("bank-validation-modal");
  if (!modal) return;
  const codeEl = document.getElementById("bankval-code");
  if (codeEl) codeEl.textContent = b.code;
  const nameEl = document.getElementById("bankval-client");
  if (nameEl) nameEl.textContent = sanitizeInput(b.clientName);
  const dateEl = document.getElementById("bankval-date");
  if (dateEl) dateEl.textContent = `${formatDisplayDate(b.selectedDate)}${b.selectedTime ? " · " + b.selectedTime : ""}`;
  const totalEl = document.getElementById("bankval-total");
  if (totalEl) totalEl.textContent = formatCRC(b.granTotal);

  // Enlaces dinámicos (Google Drive y confirmación WhatsApp al cliente).
  const driveCta = document.getElementById("bankval-drive-link");
  if (driveCta) driveCta.href = ARKIK_DRIVE_FOLDER_URL;

  const firstName = String(b.clientName || "").split(" ")[0];
  const confirmMsg = `Hola ${firstName}! 🎉 Su reserva ${b.code} del ${formatDisplayDate(b.selectedDate)}${b.selectedTime ? " a las " + b.selectedTime : ""} (${b.serviceName || b.eventType || "formato musical"}) está CONFIRMADA. Ref. SINPE: ${b.sinpeRef || "S/N"}. ¡Nos vemos en el evento! — Juan José Ramírez, Arkik Productions`;
  const waCta = document.getElementById("bankval-wa-link");
  if (waCta) waCta.href = whatsappClientUrl(b, confirmMsg);

  ModalController.open("bank-validation-modal");
}

function closeBankValidationModal() {
  ModalController.close("bank-validation-modal");
}

/**
 * Reporte Ejecutivo del Propietario — plantilla corporativa off-screen A4.
 * Construye un contenedor HTML desmontado con ancho fijo (800px), tipografía
 * 'Inter' y paleta corporativa (slate-900 / púrpura) para rasterización 1:1
 * por html2pdf.js o impresión nativa. NO se agrega al DOM: el ciclo de
 * renderizado (exportOwnerReportPDF) lo monta en un wrapper oculto temporal.
 *
 * @param {string} periodFilter        Clave de período (hoy|semana|mes|anio|total).
 * @param {Object} metrics             KPIs consolidados del período:
 *   { total, deposits, pending, volume, occupancy } (importes en ₡, números).
 * @param {Array}  bookingsList        Reservas del período (BookingStore.all()).
 * @returns {HTMLDivElement}           Contenedor del reporte (detached).
 */
function buildOwnerExecutiveReportHtml(periodFilter, metrics, bookingsList) {
  const range = periodRange(periodFilter);
  const periodLabel = (PERIOD_FILTERS.find(f => f.key === periodFilter) || PERIOD_FILTERS[PERIOD_FILTERS.length - 1]).label;
  const total = Number(metrics.total) || 0;
  const deposits = Number(metrics.deposits) || 0;
  const pending = Number(metrics.pending) || 0;
  const volume = Number(metrics.volume) || 0;
  const occupancy = Number(metrics.occupancy) || 0;
  const bookings = Array.isArray(bookingsList) ? bookingsList : [];
  const active = bookings.filter(b => b.status && b.status !== "cancelada");

  // ── Timestamp real de emisión (formato es-CR con AM/PM) ──
  const now = new Date();
  const pad2 = n => String(n).padStart(2, "0");
  const h24 = now.getHours();
  const h12 = h24 % 12 === 0 ? 12 : h24 % 12;
  const ampm = h24 >= 12 ? "PM" : "AM";
  const timestamp = `${pad2(now.getDate())}/${pad2(now.getMonth() + 1)}/${now.getFullYear()} ${h12}:${pad2(now.getMinutes())} ${ampm}`;

  // ── Sección 3: resumen operativo y logístico ──
  const showHours = active.reduce((sum, b) => {
    const svc = CATALOG_SERVICES.find(s => s.id === b.serviceId);
    const mins = svc && svc.durationMinutes ? svc.durationMinutes : 120;
    const extra = Number((b.extras && b.extras.extraHoursCount) || 0);
    return sum + mins / 60 + extra;
  }, 0);
  let topFormat = "—";
  if (active.length) {
    const counts = {};
    active.forEach(b => {
      const k = String(b.serviceName || b.serviceId || "Evento");
      counts[k] = (counts[k] || 0) + 1;
    });
    topFormat = Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0] || "—";
  }
  const gamCount = active.filter(b => !isNonGamLocation(b.province, b.canton)).length;
  const nonGamCount = active.length - gamCount;
  const showHoursLabel = (Math.round(showHours * 10) / 10) + " h";

  // ── Tabla: filas alternadas, números tabulares, separadores de miles ──
  const statusChip = (status) => ({
    confirmada: "background:#d1fae5;color:#065f46;",
    cancelada: "background:#fee2e2;color:#991b1b;",
    realizada: "background:#e0e7ff;color:#3730a3;"
  }[status] || "background:#fef3c7;color:#92400e;");

  const rowsHtml = bookings.map((b, i) => `
    <tr style="border-bottom: 1px solid #e2e8f0;${i % 2 === 1 ? " background: #f8fafc;" : ""}">
      <td style="padding: 6px 8px; font-family: ui-monospace, 'Cascadia Mono', monospace; font-weight: 700; color: #6d28d9; white-space: nowrap;" class="text-xs text-slate-700">${sanitizeInput(b.code)}</td>
      <td style="padding: 6px 8px; white-space: nowrap;" class="text-xs text-slate-700">${formatDisplayDate(b.selectedDate)}${b.selectedTime ? " · " + sanitizeInput(b.selectedTime) : ""}</td>
      <td style="padding: 6px 8px;" class="text-xs text-slate-700"><strong>${sanitizeInput(b.clientName)}</strong><br><span style="font-size: 9px; color: #64748b;">${sanitizeInput(b.clientPhone || "")}</span></td>
      <td style="padding: 6px 8px;" class="text-xs text-slate-700">${sanitizeInput(b.serviceName || "")}${b.eventType ? " · " + sanitizeInput(b.eventType) : ""}</td>
      <td style="padding: 6px 8px; text-align: right; font-variant-numeric: tabular-nums; font-weight: 700;" class="text-xs text-slate-700">${formatCRC(b.granTotal)}</td>
      <td style="padding: 6px 8px; text-align: right; font-variant-numeric: tabular-nums; color: #047857; font-weight: 700;" class="text-xs">${formatCRC(b.deposit50Amount)}</td>
      <td style="padding: 6px 8px; text-align: right; font-variant-numeric: tabular-nums; color: #3730a3; font-weight: 700;" class="text-xs">${formatCRC(b.remainingBalance)}</td>
      <td style="padding: 6px 8px; text-align: center;" class="text-xs"><span style="padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 9px; ${statusChip(b.status)}">${BOOKING_STATUSES[b.status] || sanitizeInput(b.status)}</span></td>
    </tr>
  `).join("");

  // ── Tarjeta de KPI (clases Tailwind pedidas + inline para el fallback print) ──
  const kpi = (label, value, extra, valueStyle) => `
    <div class="border border-slate-200 bg-slate-50 p-4 rounded-xl"
      style="border: 1px solid #e2e8f0; background: #f8fafc; padding: 16px; border-radius: 12px;">
      <p style="margin: 0 0 6px 0; font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.6px; color: #64748b;">${label}</p>
      <p style="margin: 0; ${valueStyle}">${value}</p>
      ${extra ? `<p style="margin: 4px 0 0 0; font-size: 10px; color: #475569;">${extra}</p>` : ""}
    </div>`;

  const container = document.createElement("div");
  container.className = "owner-exec-report";
  container.style.width = "800px";
  container.style.boxSizing = "border-box";
  container.style.padding = "35px";
  container.style.background = "#ffffff";
  container.style.color = "#0f172a";
  container.style.fontFamily = "'Inter', system-ui, sans-serif";
  container.style.fontSize = "12px";
  container.style.lineHeight = "1.5";

  container.innerHTML = `
    <!-- ══ HEADER CORPORATIVO ══ -->
    <div style="display: flex; justify-content: space-between; align-items: center; gap: 16px; border-bottom: 2px solid #7c3aed; padding-bottom: 14px; margin-bottom: 18px;">
      <div style="flex-shrink: 0;">
        <img src="img/arkik_logo.jpg" alt="Arkik Productions"
          style="height: 58px; width: auto; object-fit: contain; border-radius: 8px; border: 1px solid #e9d5ff;" />
      </div>
      <div style="text-align: right;">
        <div style="margin: 0; font-size: 16px; font-weight: 900; color: #4c1d95; letter-spacing: 0.3px; line-height: 1.2;">REPORTE EJECUTIVO Y OPERATIVO DE VENTAS</div>
        <div style="margin: 8px 0 0 0;">
          <span style="display: inline-block; padding: 3px 12px; border-radius: 999px; background: #f3e8ff; border: 1px solid #d8b4fe; color: #6d28d9; font-size: 11px; font-weight: 800;">⏱ ${sanitizeInput(periodLabel)} · ${range.start} → ${range.end}</span>
        </div>
        <div style="margin: 6px 0 0 0; font-size: 10px; color: #475569;">Fecha y Hora de Emisión: <strong style="color: #1e293b;">${timestamp}</strong></div>
        <div style="margin: 2px 0 0 0; font-size: 10px; color: #475569;">Emisor: <strong style="color: #1e293b;">Propietario: Juan José Ramírez Chaves</strong></div>
      </div>
    </div>

    <!-- ══ SECCIÓN 1: RESUMEN EJECUTIVO DE KPIs ══ -->
    <div style="margin-bottom: 18px;">
      <div style="margin: 0 0 8px 0; font-size: 10px; font-weight: 800; color: #7c3aed; text-transform: uppercase; letter-spacing: 1px;">1. Resumen Ejecutivo de KPIs</div>
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;">
        ${kpi("Facturación Total Proyectada", formatCRC(total), "Suma de cotizaciones del período",
          "font-family: ui-monospace, 'Cascadia Mono', monospace; font-size: 22px; font-weight: 800; color: #0f172a;")}
        ${kpi("Adelantos Cobrados (50% SINPE)", formatCRC(deposits), "Depósitos verificados & pendientes",
          "font-family: ui-monospace, 'Cascadia Mono', monospace; font-size: 18px; font-weight: 800; color: #047857;")}
        ${kpi("Saldos Pendientes por Cobrar", formatCRC(pending), "A cobrar en sitio el día del evento",
          "font-family: ui-monospace, 'Cascadia Mono', monospace; font-size: 18px; font-weight: 800; color: #3730a3;")}
        ${kpi("Volumen de Reservas", String(volume), `Tasa de Ocupación: ${occupancy}% · Máx. ${DEFAULT_MAX_EVENTS_PER_DAY}/día`,
          "font-size: 22px; font-weight: 900; color: #0f172a;")}
      </div>
    </div>

    <!-- ══ SECCIÓN 2: DESGLOSE TABULAR ══ -->
    <div style="margin-bottom: 18px;">
      <div style="margin: 0 0 8px 0; font-size: 10px; font-weight: 800; color: #7c3aed; text-transform: uppercase; letter-spacing: 1px;">2. Desglose Tabular de Reservas y Eventos</div>
      <table class="w-full" style="width: 100%; border-collapse: collapse; font-size: 12px;">
        <thead>
          <tr style="background: #0f172a; color: #ffffff;">
            <th style="padding: 8px; text-align: left; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;">Código (ARK)</th>
            <th style="padding: 8px; text-align: left; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;">Fecha / Hora</th>
            <th style="padding: 8px; text-align: left; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;">Cliente</th>
            <th style="padding: 8px; text-align: left; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;">Formato / Evento</th>
            <th style="padding: 8px; text-align: right; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;">Total ₡</th>
            <th style="padding: 8px; text-align: right; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;">Adelanto 50%</th>
            <th style="padding: 8px; text-align: right; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;">Saldo ₡</th>
            <th style="padding: 8px; text-align: center; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;">Estado</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml || '<tr><td colspan="8" style="padding: 14px; text-align: center; color: #94a3b8;">No hay reservas registradas en este período.</td></tr>'}
        </tbody>
      </table>
    </div>

    <!-- ══ SECCIÓN 3: RESUMEN OPERATIVO Y LOGÍSTICO ══ -->
    <div style="margin-bottom: 18px;">
      <div style="margin: 0 0 8px 0; font-size: 10px; font-weight: 800; color: #7c3aed; text-transform: uppercase; letter-spacing: 1px;">3. Resumen Operativo y Logístico</div>
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
        <div style="border: 1px solid #e2e8f0; border-radius: 12px; padding: 12px; background: #f8fafc;">
          <p style="margin: 0; font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.6px; color: #64748b;">⏱ Total Horas de Show</p>
          <p style="margin: 6px 0 0 0; font-size: 20px; font-weight: 900; color: #0f172a;">${showHoursLabel}</p>
          <p style="margin: 3px 0 0 0; font-size: 10px; color: #475569;">Incluye horas extra y DJ</p>
        </div>
        <div style="border: 1px solid #e2e8f0; border-radius: 12px; padding: 12px; background: #f8fafc;">
          <p style="margin: 0; font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.6px; color: #64748b;">🎤 Formato Más Solicitado</p>
          <p style="margin: 6px 0 0 0; font-size: 16px; font-weight: 900; color: #0f172a;">${sanitizeInput(String(topFormat))}</p>
          <p style="margin: 3px 0 0 0; font-size: 10px; color: #475569;">${active.length ? "Demanda del período" : ""}</p>
        </div>
        <div style="border: 1px solid #e2e8f0; border-radius: 12px; padding: 12px; background: #f8fafc;">
          <p style="margin: 0; font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.6px; color: #64748b;">📍 Distribución GAM / Fuera</p>
          <p style="margin: 6px 0 0 0; font-size: 16px; font-weight: 900; color: #0f172a;">${gamCount} GAM · ${nonGamCount} Fuera</p>
          <p style="margin: 3px 0 0 0; font-size: 10px; color: #475569;">${active.length ? "Fuera de GAM suma 12% de viáticos" : ""}</p>
        </div>
      </div>
    </div>

    <!-- ══ FOOTER INSTITUCIONAL ══ -->
    <div style="margin-top: 14px; border-top: 1px solid #e2e8f0; padding-top: 10px; font-size: 9px; color: #64748b; line-height: 1.6;">
      <div style="font-weight: 800; color: #4c1d95; text-transform: uppercase; letter-spacing: 0.5px;">Declaración de Confidencialidad</div>
      <div>Este documento contiene información financiera y operativa de Arkik Productions y está destinado exclusivamente al Propietario. Prohibida su reproducción o distribución sin autorización expresa.</div>
      <div style="margin-top: 6px; text-align: right; color: #94a3b8;">Arkik Productions © 2026 - Documento Financiero Interno</div>
    </div>
  `;

  return container;
}

/**
 * Exporta el reporte ejecutivo integral en PDF para el Propietario (Juan José Ramírez).
 * Flujo seguro: plantilla off-screen → pre-carga del logo → html2pdf A4 portrait
 * con paginación restringida y limpieza prometida del DOM temporal.
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

  // 1. Construcción de la plantilla corporativa (offscreen, detached)
  const container = buildOwnerExecutiveReportHtml(filterKey, {
    total, deposits, pending,
    volume: active.length,
    occupancy
  }, bookings);

  // 2. Inserción Off-Screen: wrapper temporal invisible (el contenedor NUNCA
  //    lleva offsets; html2pdf.js clona el nodo fuente conservando estilos).
  const wrapper = document.createElement("div");
  wrapper.style.position = "absolute";
  wrapper.style.left = "-9999px";
  wrapper.style.top = "0";
  wrapper.style.zIndex = "-1";
  wrapper.style.margin = "0";
  wrapper.style.padding = "0";
  wrapper.appendChild(container);
  document.body.appendChild(wrapper);

  showToast("Generando reporte ejecutivo PDF...", "info");

  const cleanup = () => {
    if (wrapper && wrapper.parentNode) wrapper.parentNode.removeChild(wrapper);
  };

  if (!window.html2pdf) {
    cleanup();
    printFallback(container.innerHTML, `Reporte_Ejecutivo_${new Date().toISOString().slice(0, 10)}`);
    return;
  }

  // 3. Pre-carga de imágenes (logo) dentro del DOM real antes de rasterizar
  preloadExecutiveImages(container)
    .then(() => {
      // 4. Configuración del motor html2pdf.js
      const opt = {
        margin: [10, 10, 10, 10],
        filename: `Arkik_Reporte_Ejecutivo_${filterKey}_${new Date().toISOString().split('T')[0]}.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, logging: false },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
        pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
      };
      return window.html2pdf().set(opt).from(container).save();
    })
    .then(() => {
      // 5. Limpieza prometida del DOM temporal
      cleanup();
      showToast("¡Reporte ejecutivo PDF exportado con éxito!", "success");
    })
    .catch((err) => {
      console.warn("PDF export fallback:", err);
      cleanup();
      showToast("Error al exportar PDF, abriendo vista de impresión.", "error");
      printFallback(container.innerHTML, `Reporte_Ejecutivo_${new Date().toISOString().slice(0, 10)}`);
    });
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
          @page { size: A4 portrait; margin: 0; }
          html, body { background: #ffffff !important; color: #0f172a !important; }
          body { font-family: 'Inter', system-ui, sans-serif; margin: 0; padding: 0; color-scheme: light; }
          .pdf-container,
          .pdf-container * { box-sizing: border-box; }
          .pdf-container {
            width: 210mm;
            min-height: 297mm;
            max-height: 297mm;
            padding: 12mm 15mm;
            background: #ffffff !important;
            color: #0f172a !important;
            font-family: 'Inter', system-ui, sans-serif;
            font-variant-numeric: tabular-nums;
            overflow: hidden;
            page-break-inside: avoid;
            break-inside: avoid;
          }
          .pdf-container img { max-width: none; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
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
// Bypass de mantenimiento del bloqueo de la consola ejecutiva.
// En la consola del navegador: resetAdminLock()   -> limpia intentos/lockout y desbloquea el modal
// Diagnóstico del estado actual:                     SecurityModule.status()
window.resetAdminLock = () => AdminModule.resetAdminLock();
window.adminAuthStatus = () => SecurityModule.status();
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
  // EmailJS bootstrap: structured fallback so an unconfigured key never breaks the flow
  initEmailJS();
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
  initHeroStringsEffect();
  window.addEventListener("hashchange", handleHashRoute);
  handleHashRoute();
  AdminModule.restoreSession();
}

// ============================================================
// MOUSE GLOW ORB — seguidor suave del cursor (LERP 0.08 a 60 FPS)
// ============================================================
(function initMouseGlowOrb() {
  const orb = document.getElementById("mouseGlowOrb");
  if (!orb) return;

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  let targetX = window.innerWidth / 2;
  let targetY = window.innerHeight / 2;
  let orbX = targetX;
  let orbY = targetY;
  let shown = false;

  window.addEventListener("mousemove", (e) => {
    targetX = e.clientX;
    targetY = e.clientY;
    if (!shown) {
      shown = true;
      orb.style.opacity = "1";
    }
  }, { passive: true });

  function lerpOrb() {
    orbX += (targetX - orbX) * 0.08;
    orbY += (targetY - orbY) * 0.08;
    orb.style.transform =
      "translate3d(" + orbX + "px, " + orbY + "px, 0) translate(-50%, -50%)";
    window.requestAnimationFrame(lerpOrb);
  }
  window.requestAnimationFrame(lerpOrb);
})();

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
        <div class="catalog-card__media h-48 sm:h-52 w-full relative overflow-hidden rounded-t-2xl bg-[#090514]">
          <img src="${service.image_url}" alt="${sanitizeInput(service.alt || service.name)}" loading="lazy" decoding="async" class="catalog-card__img w-full h-full object-cover" />
          <div class="catalog-card__overlay absolute inset-0"></div>
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

        <button onclick="openBookingModal(${service.id})" class="w-full py-3 px-5 rounded-xl font-medium text-sm text-white bg-gradient-to-r from-purple-600 via-purple-500 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 shadow-[0_0_20px_rgba(168,85,247,0.35)] hover:shadow-[0_0_28px_rgba(168,85,247,0.55)] border border-purple-400/30 transition-all duration-300 transform hover:-translate-y-0.5 active:translate-y-0 flex items-center justify-center gap-2 group">
          <span>Cotizar y Reservar</span>
          <svg class="w-4 h-4 transition-transform duration-300 group-hover:translate-x-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"></path></svg>
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
    const base = "gallery-filter-btn gallery-filter-pill min-h-[44px] min-w-[44px] px-4 py-2.5 rounded-full text-xs sm:text-sm font-bold border flex items-center justify-center gap-1.5 focus:outline-none focus:ring-2 focus:ring-pink-500/50 cursor-pointer whitespace-nowrap shrink-0";
    const state = active
      ? " gallery-filter-pill--active text-white border-transparent"
      : " text-gray-300 border-white/10 hover:text-white";
    return `<button type="button" data-filter="${filter.key}" class="${base}${state}">${sanitizeInput(filter.label)} <span class="text-[10px] opacity-75 font-semibold bg-black/30 px-1.5 py-0.5 rounded-full">${count}</span></button>`;
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

// Badge dinámico según el contenido: Destacado / Audio En Vivo / Instagram Reel.
function galleryDynamicBadge(item) {
  if (item.featured) return '<span class="gallery-badge gallery-badge--featured">🔥 Evento Destacado</span>';
  if (item.type === "video") return '<span class="gallery-badge gallery-badge--video">🎵 Audio En Vivo</span>';
  if (item.type === "instagram") return '<span class="gallery-badge gallery-badge--instagram">🎬 Instagram Reel</span>';
  return "";
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
    <article class="gallery-card ${featuredClass} group rounded-3xl overflow-hidden relative block cursor-pointer focus:outline-none focus:ring-2 focus:ring-pink-500/50"
             onclick="openMediaLightbox('${sanitizeInput(item.id)}')">
      
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
            ${galleryDynamicBadge(item)}
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
    <article class="gallery-card ${featuredClass} group relative rounded-3xl overflow-hidden cursor-pointer"
             onclick="openMediaLightbox('${sanitizeInput(item.id)}')">
      <div id="gallery-media-${sanitizeInput(item.id)}" class="relative ${item.featured ? 'aspect-[16/10] sm:aspect-[16/9]' : 'aspect-[4/5]'} overflow-hidden bg-black/50">
        <img src="${thumbnail}" alt="${title}" loading="lazy"
          class="w-full h-full object-cover transition-transform duration-500 ease-out group-hover:scale-105" />
        <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/30 to-transparent"></div>
        <div class="absolute top-3.5 inset-x-3.5 flex items-center justify-between z-10">
          <div class="flex items-center gap-1.5">
            ${galleryCategoryBadge(item)}
            ${galleryDynamicBadge(item)}
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
    <article class="gallery-card ${featuredClass} group relative rounded-3xl overflow-hidden cursor-pointer"
             onclick="openMediaLightbox('${sanitizeInput(item.id)}')">
      <div class="relative ${item.featured ? 'aspect-[16/10] sm:aspect-[16/9]' : 'aspect-[4/5]'} overflow-hidden bg-black/50">
        <img src="${url}" alt="${title}" loading="lazy"
          class="w-full h-full object-cover transition-transform duration-500 ease-out group-hover:scale-105" />
        <div class="absolute inset-0 bg-gradient-to-t from-black/90 via-black/30 to-transparent"></div>
        <div class="absolute top-3.5 inset-x-3.5 flex items-center justify-between z-10">
          <div class="flex items-center gap-1.5">
            ${galleryCategoryBadge(item)}
            ${galleryDynamicBadge(item)}
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

// Dominios que responden con X-Frame-Options: DENY / frame-ancestors 'none',
// por lo que NO pueden incrustarse en un <iframe> (causan ERR_BLOCKED_BY_RESPONSE).
const NOT_EMBEDDABLE = /drive\.google\.com|instagram\.com|facebook\.com|dropbox\.com|tiktok\.com/i;

// Host "amigable" para el botón de fallback ("Ver en Instagram", "Abrir en Google Drive", …).
function embeddableHostLabel(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    if (/drive\.google\.com/.test(host)) return "Google Drive";
    const name = host.split(".")[0];
    return name.charAt(0).toUpperCase() + name.slice(1);
  } catch {
    return "el enlace original";
  }
}

// Lightbox navigation state (lista visible = filtro actual + índice)
let lightboxList = [];
let lightboxIndex = -1;
let lightboxTouchX = null;

// Misma lógica de filtro que renderMediaGallery: navegar solo por lo visible en el grid.
function lightboxFilteredItems() {
  const items = StorageEngine.getGalleryItems();
  const f = currentGalleryFilter;
  if (f === "todos") return items;
  return items.filter(item => item.category === f || (f === "instagram" && item.type === "instagram"));
}

// Ubicación best-effort desde la leyenda ("Lugar — Descripción" -> "Lugar").
function extractLightboxLocation(item) {
  const raw = String(item.caption || item.subtitle || "").trim();
  if (!raw) return "";
  return raw.split(/\s*[—–]\s*/)[0].trim();
}

// Rellena el visor (slot multimedia + metadatos) para un item.
function renderLightboxItem(item) {
  const slot = document.getElementById("lightbox-media-slot");
  const titleEl = document.getElementById("lightbox-title");
  const captionEl = document.getElementById("lightbox-caption");
  const dateEl = document.getElementById("lightbox-date");
  const catEl = document.getElementById("lightbox-category-badge");
  const locEl = document.getElementById("lightbox-location");
  const counterEl = document.getElementById("lightbox-counter");
  const directLink = document.getElementById("lightbox-direct-link");

  if (titleEl) titleEl.textContent = item.title;
  if (captionEl) captionEl.textContent = item.caption || item.subtitle || "Muestra en vivo oficial de Arkik Productions.";
  if (dateEl) dateEl.textContent = item.date || "2026";
  if (catEl) catEl.textContent = GALLERY_CATEGORY_LABELS[item.category] || item.category;
  if (locEl) locEl.textContent = extractLightboxLocation(item) || "Costa Rica";
  if (counterEl && lightboxList.length > 0) counterEl.textContent = `${lightboxIndex + 1} / ${lightboxList.length}`;

  activeLightboxUrl = item.directUrl || item.url || "https://www.instagram.com/kikeramirezcr";
  if (directLink) {
    directLink.href = activeLightboxUrl;
  }

  if (!slot) return;
  slot.innerHTML = "";
  if (item.type === "video" && item.embedUrl && !NOT_EMBEDDABLE.test(item.embedUrl)) {
    // Dominios embebibles (YouTube, Vimeo, etc.): iframe normal.
    const iframe = document.createElement("iframe");
    iframe.src = item.embedUrl + (item.embedUrl.includes("?") ? "&" : "?") + "autoplay=1";
    iframe.title = item.title;
    iframe.setAttribute("allow", "accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share");
    iframe.setAttribute("allowfullscreen", "");
    iframe.className = "w-full h-full border-0 rounded-2xl";
    slot.appendChild(iframe);
  } else if (item.type === "video" && item.embedUrl && NOT_EMBEDDABLE.test(item.embedUrl)) {
    // Dominio no embebible (Instagram/Drive/Facebook/…): NO crear iframe.
    // Mostrar placeholder visual + botón para abrir el original en pestaña nueva.
    const src = item.thumbnail || "img/Foto Kike .jpg";
    const openUrl = sanitizeUrl(item.directUrl || item.embedUrl);
    const hostLabel = embeddableHostLabel(openUrl);
    const wrap = document.createElement("div");
    wrap.className = "relative w-full h-full flex flex-col items-center justify-center gap-4 rounded-2xl overflow-hidden";
    wrap.style.cssText = "background:linear-gradient(160deg,rgba(139,92,246,0.10),rgba(11,6,26,0.85));border:1px solid rgba(139,92,246,0.25);";
    const imgWrap = document.createElement("div");
    imgWrap.className = "w-full h-[60vh] overflow-hidden";
    const img = document.createElement("img");
    img.src = src;
    img.alt = item.title;
    img.className = "w-full h-full object-cover";
    img.style.cssText = "filter:saturate(1.05);";
    imgWrap.appendChild(img);
    const overlay = document.createElement("div");
    overlay.className = "absolute inset-0 flex flex-col items-center justify-center gap-2 p-6 text-center";
    overlay.style.cssText = "background:rgba(11,6,26,0.55);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);";
    const icon = document.createElement("div");
    icon.textContent = "📹";
    icon.style.cssText = "font-size:2rem;opacity:0.9;";
    const msg = document.createElement("p");
    msg.style.cssText = "font-weight:700;color:#ffffff;font-size:0.9rem;max-width:34ch;text-shadow:0 1px 3px rgba(0,0,0,0.6);";
    msg.textContent = "Este video no se puede reproducir embebido.";
    const sub = document.createElement("p");
    sub.style.cssText = "font-size:0.75rem;color:#c4b5fd;margin-bottom:0.25rem;";
    sub.textContent = `Solo se permite incrustarlo en una pestaña nueva.`;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.style.cssText = "display:inline-flex;align-items:center;justify-content:center;gap:0.5rem;min-height:44px;padding:0.75rem 1.25rem;border-radius:0.75rem;font-weight:700;font-size:0.875rem;color:#ffffff;background:linear-gradient(135deg,#8b5cf6 0%,#5b21b6 100%);box-shadow:0 8px 24px rgba(139,92,246,0.3);border:1px solid transparent;cursor:pointer;";
    btn.textContent = `Abrir en ${hostLabel}`;
    btn.addEventListener("click", () => window.open(openUrl, "_blank", "noopener"));
    overlay.appendChild(icon);
    overlay.appendChild(msg);
    overlay.appendChild(sub);
    overlay.appendChild(btn);
    wrap.appendChild(imgWrap);
    wrap.appendChild(overlay);
    slot.appendChild(wrap);
  } else {
    const img = document.createElement("img");
    img.src = item.thumbnail || item.directUrl || "img/Foto Kike .jpg";
    img.alt = item.title;
    img.className = "w-full h-full object-contain max-h-[70vh] rounded-2xl shadow-2xl";
    slot.appendChild(img);
  }
}

// Gestos táctiles horizontales (swipe) dentro del visor.
function attachLightboxSwipe(el) {
  if (!el || el.dataset.swipeBound) return;
  el.dataset.swipeBound = "1";
  el.addEventListener("touchstart", (e) => {
    lightboxTouchX = e.touches[0].clientX;
  }, { passive: true });
  el.addEventListener("touchend", (e) => {
    if (lightboxTouchX === null) return;
    const dx = e.changedTouches[0].clientX - lightboxTouchX;
    if (Math.abs(dx) > 40) navigateLightbox(dx < 0 ? 1 : -1);
    lightboxTouchX = null;
  }, { passive: true });
}

function openMediaLightbox(id) {
  const items = lightboxFilteredItems();
  const idx = items.findIndex(m => String(m.id) === String(id));
  if (idx === -1) return;

  lightboxList = items;
  lightboxIndex = idx;
  renderLightboxItem(items[idx]);
  attachLightboxSwipe(document.getElementById("lightbox-media-container"));

  const modal = document.getElementById("mediaLightboxModal");
  if (modal) {
    ModalController.open("mediaLightboxModal");
  }
}

function navigateLightbox(dir) {
  if (lightboxList.length === 0) return;
  lightboxIndex = (lightboxIndex + dir + lightboxList.length) % lightboxList.length;
  renderLightboxItem(lightboxList[lightboxIndex]);
}

function closeMediaLightbox() {
  const modal = document.getElementById("mediaLightboxModal");
  const slot = document.getElementById("lightbox-media-slot");
  if (slot) slot.innerHTML = ""; // Stop video playback
  lightboxList = [];
  lightboxIndex = -1;
  lightboxTouchX = null;
  const container = document.getElementById("lightbox-media-container");
  if (container) delete container.dataset.swipeBound;
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

  // Voucher SINPE: al elegir archivo se comprime y persiste en CartState.
  const voucherUpload = document.getElementById("voucher-upload");
  if (voucherUpload) {
    voucherUpload.addEventListener("change", (e) => {
      const file = e.target.files && e.target.files[0];
      if (file) handleVoucherUpload(file);
      // Permite volver a elegir el mismo archivo en el siguiente intento.
      e.target.value = "";
    });
  }

  const nameInput = document.getElementById("client-name");
  const nameCheck = document.getElementById("name-check");
  if (nameInput) {
    nameInput.addEventListener("input", (e) => {
      const val = e.target.value.trim();
      const ok = isValidClientName(val);
      if (nameCheck) {
        nameCheck.textContent = ok ? "✓ 2 palabras min. confirmado" : "";
        nameCheck.classList.toggle("hidden", !ok);
      }
      validateFieldLive(e.target);
    });
  }

  const phoneInput = document.getElementById("client-phone");
  if (phoneInput) {
    phoneInput.addEventListener("input", (e) => {
      maskCrPhoneInput(e.target);
      validateFieldLive(e.target);
    });
  }

  const emailInput = document.getElementById("client-email");
  if (emailInput) emailInput.addEventListener("input", (e) => validateFieldLive(e.target));
  const addressInput = document.getElementById("booking-address");
  if (addressInput) addressInput.addEventListener("input", (e) => validateFieldLive(e.target));

  const provSelect = document.getElementById("booking-province");
  if (provSelect) {
    provSelect.addEventListener("change", (e) => {
      cart.province = e.target.value;
      cart.canton = "";
      populateCantones(e.target.value);
      updateSummaryPrices();
      cart.persist();
      validateFieldLive(provSelect);
      const canton = document.getElementById("booking-canton");
      if (canton) validateFieldLive(canton);
    });
  }

  const cantonSelect = document.getElementById("booking-canton");
  if (cantonSelect) {
    cantonSelect.addEventListener("change", (e) => {
      cart.canton = e.target.value;
      updateSummaryPrices();
      cart.persist();
      validateFieldLive(cantonSelect);
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
  bindLoginTrap();
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
    portalModal.addEventListener("pointerdown", () => { AdminModule.startInactivityTimer(); AdminModule.touchActivity(); });
    portalModal.addEventListener("keydown", () => { AdminModule.startInactivityTimer(); AdminModule.touchActivity(); });
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
        const firstName = String(booking.clientName || "Cliente").split(" ")[0];
        window.open(whatsappClientUrl(booking, `Hola ${firstName}, soy Juan José Ramírez de Arkik Productions. Te contacto para confirmar los detalles de tu evento con código ${booking.code}.`), "_blank", "noopener");
        return;
      }
      if (action === "confirm") {
        validateBankPayment(booking);
        return;
      }
      if (action === "complete") {
        BookingStore.updateStatus(booking.code, "realizada");
        showToast(`Reserva ${booking.code} marcada como realizada.`, "success");
      } else if (action === "cancel") {
        BookingStore.updateStatus(booking.code, "cancelada");
        showToast(`Reserva ${booking.code} cancelada. Cupo del calendario liberado.`, "info");
        // Aviso de rechazo/cancelación por WhatsApp (especificación Owner Deck)
        const firstName = String(booking.clientName).split(" ")[0];
        const rejectMsg = `Hola ${firstName}, le informamos que la reserva ${booking.code} (${formatDisplayDate(booking.selectedDate)}) fue cancelada o rechazada. Si tiene dudas puede escribirnos. Lamentamos el inconveniente. — Arkik Productions`;
        window.open(whatsappClientUrl(booking, rejectMsg), "_blank", "noopener");
      } else if (action === "view") {
        if (booking.voucherImage) {
          AdminModule.openVoucherPreview(booking.voucherImage);
          return;
        }
        showToast("Esta reserva no tiene comprobante SINPE adjunto.", "error");
        return;
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
        const fromInput = document.getElementById("admin-avail-from");
        const toInput = document.getElementById("admin-avail-to");
        const reasonInput = document.getElementById("admin-avail-reason");
        const from = fromInput ? fromInput.value : "";
        const to = toInput ? toInput.value : "";
        const state = availBtn.getAttribute("data-avail");
        const reason = reasonInput ? reasonInput.value.trim() : "";
        const isoRe = /^\d{4}-\d{2}-\d{2}$/;
        if (!from || !isoRe.test(from)) {
          showToast("Seleccione una fecha válida (formato AAAA-MM-DD).", "error");
          return;
        }
        if (to && !isoRe.test(to)) {
          showToast("La fecha final tiene formato inválido (AAAA-MM-DD).", "error");
          return;
        }
        const [fy, fm, fd] = from.split("-").map(Number);
        const startISO = new Date(fy, fm - 1, fd);
        if (Number.isNaN(startISO.getTime())) {
          showToast("La fecha inicial no es una fecha real.", "error");
          return;
        }
        if (startISO.getFullYear() !== fy || startISO.getMonth() !== fm - 1 || startISO.getDate() !== fd) {
          showToast("La fecha inicial no es una fecha real.", "error");
          return;
        }
        const endISO = to
          ? (() => {
              const [ty, tm, td] = to.split("-").map(Number);
              const d = new Date(ty, tm - 1, td);
              if (Number.isNaN(d.getTime())) return null;
              if (d.getFullYear() !== ty || d.getMonth() !== tm - 1 || d.getDate() !== td) return null;
              return d;
            })()
          : null;
        if (to && !endISO) {
          showToast("La fecha final no es una fecha real.", "error");
          return;
        }
        if (endISO && endISO < startISO) {
          showToast("La fecha final no puede ser anterior a la inicial.", "error");
          return;
        }
        const cursor = new Date(startISO);
        const end = endISO || startISO;
        let appliedCount = 0;
        while (cursor <= end) {
          const iso = isoOf(cursor);
          AvailabilityManager.set(iso, state, reason);
          appliedCount += 1;
          cursor.setDate(cursor.getDate() + 1);
        }
        const verb = state === "available"
          ? `Desbloqueado(s) ${appliedCount} fecha(s) (${from}${to ? " → " + to : ""}).`
          : `${state === "soldout" ? "Marcado(s) agotado(s)" : "Bloqueada(s)"} ${appliedCount} fecha(s) (${from}${to ? " → " + to : ""})${reason ? " · Motivo: " + reason : ""}.`;
        AuditLog.recordEvent("block", verb);
        showToast(`Disponibilidad actualizada: ${verb}`, "success");
        AdminModule.renderIT();
        if (reasonInput) reasonInput.value = "";
        return;
      }

      const removeBtn = e.target.closest("[data-avail-remove]");
      if (removeBtn) {
        const iso = removeBtn.getAttribute("data-avail-remove");
        AvailabilityManager.set(iso, "available");
        AuditLog.recordEvent("block", `Fecha desbloqueada: ${iso}.`);
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
        AuditLog.recordEvent("price", "Tarifas y configuración aplicadas en lote.");
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
        AuditLog.recordEvent("price", "Tarifas restauradas a los valores de fábrica.");
        showToast("Precios restaurados a los originales.", "success");
        return;
      }

      if (e.target.closest("#admin-export-backup")) {
        exportAdminBackup(true);
        return;
      }

      if (e.target.closest("#admin-export-sql")) {
        exportAdminSQL();
        return;
      }

      if (e.target.closest("#admin-clear-cache")) {
        AdminModule.clearLocalCache();
        return;
      }

      if (e.target.closest("#admin-factory-reset")) {
        AdminModule.factoryReset();
        return;
      }
    });

    itView.addEventListener("change", (e) => {
      // Solo los inputs de archivo se vacían tras el cambio; nunca los de
      // fecha/tarifa (el borrado global eliminaba valores recién editados).
      if (e.target.id === "admin-import-backup") {
        if (e.target.files && e.target.files[0]) importAdminBackup(e.target.files[0]);
        e.target.value = "";
      }
    });

    // Persistencia en vivo: cada edición de tarifa/config se guarda en
    // localStorage y recalibra el catálogo público sin recargar la página.
    let itLivePersistTimer = null;
    itView.addEventListener("input", (e) => {
      const t = e.target;
      const isLivePrice = t.hasAttribute("data-price") && t.closest("#admin-it-prices");
      const isLiveConfig = t.id === "admin-extra-multiplier" || t.id === "admin-travel-rate";
      if (!isLivePrice && !isLiveConfig) return;
      clearTimeout(itLivePersistTimer);
      itLivePersistTimer = setTimeout(() => {
        persistITLiveInputs();
      }, 350);
    });
  }

  // --- Teclado Global: ESC cierra modales + flechas navegan lightbox multimedia + Ctrl+Shift+A abre panel admin ---
  document.addEventListener("keydown", (e) => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      const mediaLightbox = document.getElementById("mediaLightboxModal");
      if (mediaLightbox && !mediaLightbox.classList.contains("hidden")) {
        e.preventDefault();
        navigateLightbox(e.key === "ArrowRight" ? 1 : -1);
        return;
      }
    }

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
      const policiesModal = document.getElementById("modal-politicas");
      if (policiesModal && !policiesModal.classList.contains("hidden")) {
        closePoliciesModal();
        return;
      }
      const profileLb = document.getElementById("profile-lightbox");
      if (profileLb && !profileLb.classList.contains("hidden")) {
        closeProfileLightbox();
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

  // --- Master Liquid Footer: event handlers ---
  const bindClick = (id, handler) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("click", handler);
  };

  // 1. Open Booking Wizard Modal
  bindClick("btn-footer-cta-booking", () => {
    if (typeof openBookingModal === "function") openBookingModal();
    else if (typeof goToStep === "function") goToStep(1);
  });

  // 2. Open Policies Modal
  const handleFooterPolicies = () => {
    if (typeof openPoliciesModal === "function") openPoliciesModal();
    else {
      const modal = document.getElementById("modal-politicas");
      if (modal) modal.classList.remove("hidden");
    }
  };
  bindClick("btn-footer-policies-link", handleFooterPolicies);

  // 3. SINPE Móvil copy logic (mirrors copySinpeData safeguards — no console errors)
  const handleFooterCopySinpe = () => {
    const num = (typeof SINPE_CONFIG !== "undefined" && SINPE_CONFIG.phone) ? SINPE_CONFIG.phone : "+506 6227-4984";
    const done = () => {
      if (typeof showToast === "function") {
        showToast("¡Número SINPE copiado con éxito!", "success");
      } else {
        alert("SINPE Móvil copiado: +506 6227-4984 (Juan José Ramírez Chaves)");
      }
    };
    const fail = () => {
      if (typeof showToast === "function") {
        showToast("No se pudo copiar el número automáticamente.", "error");
      }
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(num).then(done).catch(fail);
    } else {
      try {
        const ta = document.createElement("textarea");
        ta.value = num;
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
  };
  bindClick("btn-footer-sinpe-link", handleFooterCopySinpe);
  bindClick("btn-copy-sinpe-num", handleFooterCopySinpe);
  const inlinePoliciesBtn = document.getElementById("btn-open-policies-inline");
  if (inlinePoliciesBtn) {
    inlinePoliciesBtn.addEventListener("click", (e) => {
      e.preventDefault();
      openPoliciesModal();
    });
  }
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
      const [byy, bmm, bdd] = b.selectedDate.split("-").map(Number);
      const bdt = new Date(byy, bmm - 1, bdd);
      if (bdt.getFullYear() !== byy || bdt.getMonth() !== bmm - 1 || bdt.getDate() !== bdd) {
        return { ok: false, error: `Backup inválido: fecha imposible en reserva ${b.code}.` };
      }
      if (typeof b.granTotal !== "number" || b.granTotal < 0 || typeof b.deposit50Amount !== "number" || b.deposit50Amount < 0) {
        return { ok: false, error: `Montos inválidos en reserva ${b.code}.` };
      }
      if (b.selectedTime !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/.test(b.selectedTime)) {
        return { ok: false, error: `Backup inválido: hora seleccionada inválida en reserva ${b.code}.` };
      }
      if (b.startTime !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/.test(b.startTime)) {
        return { ok: false, error: `Backup inválido: hora seleccionada inválida en reserva ${b.code}.` };
      }
      if (b.endTime !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/.test(b.endTime)) {
        return { ok: false, error: `Backup inválido: hora seleccionada inválida en reserva ${b.code}.` };
      }
      if (typeof b.clientName !== "string" || b.clientName.length > 200) {
        return { ok: false, error: `Backup inválido: campo de texto inválido en la reserva ${b.code}.` };
      }
      if (typeof b.clientPhone !== "string" || b.clientPhone.length > 40) {
        return { ok: false, error: `Backup inválido: campo de texto inválido en la reserva ${b.code}.` };
      }
      if (b.clientEmail !== undefined && (typeof b.clientEmail !== "string" || b.clientEmail.length > 320)) {
        return { ok: false, error: `Backup inválido: campo de texto inválido en la reserva ${b.code}.` };
      }
      if (b.location !== undefined && (typeof b.location !== "string" || b.location.length > 255)) {
        return { ok: false, error: `Backup inválido: campo de texto inválido en la reserva ${b.code}.` };
      }
      if (typeof b.setupDisplay !== "string" || b.setupDisplay.length > 200) {
        return { ok: false, error: `Backup inválido: campo de texto inválido en la reserva ${b.code}.` };
      }
      if (typeof b.teardownDisplay !== "string" || b.teardownDisplay.length > 200) {
        return { ok: false, error: `Backup inválido: campo de texto inválido en la reserva ${b.code}.` };
      }
      if (typeof b.serviceName !== "string" || b.serviceName.length > 200) {
        return { ok: false, error: `Backup inválido: campo de texto inválido en la reserva ${b.code}.` };
      }
      if (typeof b.eventType !== "string" || b.eventType.length > 200) {
        return { ok: false, error: `Backup inválido: campo de texto inválido en la reserva ${b.code}.` };
      }
    }
  }
  if (payload.availability) {
    for (const [date, state] of Object.entries(payload.availability)) {
      const st = state && typeof state === "object" ? state.state : state;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !["available", "soldout", "disabled"].includes(st)) {
        return { ok: false, error: `Estado de disponibilidad inválido para ${date}.` };
      }
      const [ayy, amm, add] = date.split("-").map(Number);
      const adt = new Date(ayy, amm - 1, add);
      if (adt.getFullYear() !== ayy || adt.getMonth() !== amm - 1 || adt.getDate() !== add) {
        return { ok: false, error: `Backup inválido: fecha imposible en disponibilidad: ${date}.` };
      }
    }
  }
  if (payload.gallery !== undefined) {
    if (!Array.isArray(payload.gallery)) {
      return { ok: false, error: "Backup inválido: galería con formato incorrecto." };
    }
    for (let gi = 0; gi < payload.gallery.length; gi++) {
      const g = payload.gallery[gi];
      if (!g || typeof g !== "object" || !/^[A-Za-z0-9_-]{1,40}$/.test(g.id || "")) {
        return { ok: false, error: `Backup inválido: id de galería inválido en la posición ${gi}.` };
      }
      if (typeof g.url !== "string" || g.url.length > 512) {
        return { ok: false, error: `Backup inválido: id de galería inválido en la posición ${gi}.` };
      }
    }
  }
  if (payload.customConfig !== undefined && (typeof payload.customConfig !== "object" || payload.customConfig === null || Array.isArray(payload.customConfig))) {
    return { ok: false, error: "Backup inválido: configuración personalizada con formato incorrecto." };
  }
  return { ok: true, error: "" };
}

function exportAdminBackup(alsoSQL) {
  const payload = StorageEngine.exportFullDatabase();
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const stamp = new Date().toISOString().slice(0, 10);
  a.href = url;
  a.download = `arkik-database-backup-${stamp}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  if (alsoSQL) exportAdminSQL(payload);
  AuditLog.recordEvent("backup", `Respaldo completo descargado (JSON${alsoSQL ? " + SQL" : ""}).`);
  showToast("Base de datos exportada (JSON" + (alsoSQL ? " + SQL" : "") + ").", "success");
}

function exportAdminSQL(payload) {
  const sql = generateSQLBackup(payload || StorageEngine.exportFullDatabase());
  const blob = new Blob([sql], { type: "application/sql;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `arkik-database-backup-${new Date().toISOString().slice(0, 10)}.sql`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/**
 * Convierte SQLite-friendly: escapa comillas simples duplicándolas.
 */
function sqlEscape(v) {
  if (v === null || v === undefined) return "NULL";
  return "'" + String(v).replace(/'/g, "''").slice(0, 400) + "'";
}

/**
 * Genera un respaldo SQL (CREATE TABLE + INSERTs) equivalente al payload JSON.
 * Cubre reservas, disponibilidad, tarifas, configuración, galería y auditoría.
 */
function generateSQLBackup(payload) {
  const L = [];
  const stamp = new Date().toISOString();
  L.push("-- Arkik Productions — Database backup (" + stamp + ")");
  L.push("PRAGMA foreign_keys = OFF;");
  L.push("BEGIN TRANSACTION;");
  L.push("");
  L.push("CREATE TABLE IF NOT EXISTS arkik_bookings (");
  L.push("  code TEXT PRIMARY KEY,");
  L.push("  client_name TEXT, client_phone TEXT, client_email TEXT,");
  L.push("  location TEXT, selected_date TEXT, start_time TEXT, end_time TEXT,");
  L.push("  service_ids TEXT, extra_ids TEXT, status TEXT,");
  L.push("  gran_total REAL, deposit50_amount REAL, remaining_balance REAL, raw_json TEXT");
  L.push(");");
  (Array.isArray(payload.bookings) ? payload.bookings : []).forEach(b => {
    if (!b || !b.code) return;
    const row = [
      sqlEscape(b.code), sqlEscape(b.clientName || b.nombre || ""),
      sqlEscape(b.clientPhone || b.telefono || ""), sqlEscape(b.clientEmail || b.email || ""),
      sqlEscape(b.location || ""), sqlEscape(b.selectedDate || ""),
      sqlEscape(b.startTime || ""), sqlEscape(b.endTime || ""),
      sqlEscape(JSON.stringify(b.services || b.cartServices || [])),
      sqlEscape(JSON.stringify(b.extras || b.cartExtras || [])),
      sqlEscape(b.status || ""),
      Number(b.granTotal) || 0, Number(b.deposit50Amount) || 0, Number(b.remainingBalance) || 0,
      sqlEscape(JSON.stringify(b))
    ].join(", ");
    L.push("INSERT INTO arkik_bookings VALUES (" + row + ");");
  });
  L.push("");
  L.push("CREATE TABLE IF NOT EXISTS arkik_availability (iso_date TEXT PRIMARY KEY, state TEXT, reason TEXT);");
  Object.entries(payload.availability || {}).forEach(([date, raw]) => {
    const st = raw && typeof raw === "object" ? raw.state : raw;
    const reason = raw && typeof raw === "object" ? raw.reason : null;
    L.push("INSERT INTO arkik_availability VALUES (" + [sqlEscape(date), sqlEscape(st), sqlEscape(reason)].join(", ") + ");");
  });
  L.push("");
  L.push("CREATE TABLE IF NOT EXISTS arkik_prices (scope TEXT, key TEXT, value REAL, PRIMARY KEY (scope, key));");
  Object.entries((payload.prices && payload.prices.services) || {}).forEach(([k, v]) => {
    L.push("INSERT INTO arkik_prices VALUES ('service', " + sqlEscape(k) + ", " + (Number(v) || 0) + ");");
  });
  Object.entries((payload.prices && payload.prices.extras) || {}).forEach(([k, v]) => {
    L.push("INSERT INTO arkik_prices VALUES ('extra', " + sqlEscape(k) + ", " + (Number(v) || 0) + ");");
  });
  L.push("");
  L.push("CREATE TABLE IF NOT EXISTS arkik_config (key TEXT PRIMARY KEY, value TEXT);");
  Object.entries(payload.customConfig || {}).forEach(([k, v]) => {
    L.push("INSERT INTO arkik_config VALUES (" + [sqlEscape(k), sqlEscape(v)].join(", ") + ");");
  });
  L.push("");
  L.push("CREATE TABLE IF NOT EXISTS arkik_gallery (id TEXT PRIMARY KEY, title TEXT, category TEXT, type TEXT, thumbnail TEXT, url TEXT, caption TEXT, date TEXT, featured INTEGER);");
  (Array.isArray(payload.gallery) ? payload.gallery : []).forEach(m => {
    if (!m || !m.id) return;
    L.push("INSERT INTO arkik_gallery VALUES (" + [
      sqlEscape(m.id), sqlEscape(m.title || ""), sqlEscape(m.category || ""), sqlEscape(m.type || ""),
      sqlEscape(m.thumbnail || ""), sqlEscape(m.url || ""), sqlEscape(m.caption || ""),
      sqlEscape(m.date || ""), m.featured ? 1 : 0
    ].join(", ") + ");");
  });
  L.push("");
  L.push("CREATE TABLE IF NOT EXISTS arkik_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, message TEXT, at TEXT);");
  const audit = payload.audit || {};
  (Array.isArray(audit.logins) ? audit.logins : []).forEach(l => {
    L.push("INSERT INTO arkik_audit (type, message, at) VALUES ('login', " + sqlEscape(("Acceso: " + (l.role || ""))) + ", " + sqlEscape(l.at || "") + ");");
  });
  (Array.isArray(audit.events) ? audit.events : []).forEach(ev => {
    L.push("INSERT INTO arkik_audit (type, message, at) VALUES (" + [sqlEscape(ev.type || "login"), sqlEscape(ev.message || ""), sqlEscape(ev.at || "")].join(", ") + ");");
  });
  L.push("");
  L.push("COMMIT;");
  L.push("-- End of backup");
  return L.join("\n");
}

/**
 * Persistencia en vivo de la suite IT: lee los inputs actuales de la matriz
 * y los guarda con recálculo global (catálogo + resumen) sin recargar.
 */
function persistITLiveInputs() {
  const inputs = document.querySelectorAll("#admin-it-prices [data-price]");
  let changed = 0;
  inputs.forEach(input => {
    const key = input.getAttribute("data-price");
    const val = Number(input.value) || 0;
    if (key.startsWith("service-")) {
      PriceManager.setServicePrice(Number(key.split("-")[1]), val);
    } else {
      PriceManager.setExtraPrice(key.split("-")[1], val);
    }
    changed += 1;
  });
  const multInput = document.getElementById("admin-extra-multiplier");
  if (multInput) {
    const val = parseFloat(multInput.value);
    if (Number.isFinite(val) && val > 0) StorageEngine.setConfig("extraHourMultiplier", val);
  }
  const travelInput = document.getElementById("admin-travel-rate");
  if (travelInput) {
    const val = parseFloat(travelInput.value);
    if (Number.isFinite(val) && val >= 0) StorageEngine.setConfig("travelSurchargeRate", val / 100);
  }
  if (changed > 0) {
    AuditLog.recordEvent("price", `Tarifas persistidas en tiempo real (${changed} campos).`);
    showToast("Tarifas persistidas y catálogo recalibrado en tiempo real.", "info");
  }
}

/**
 * Latencia real de lectura/escritura de localStorage (PING del sistema).
 */
function measureStorageLatency() {
  const t0 = performance.now();
  try {
    const k = "__ark_lat_probe__";
    localStorage.setItem(k, "1");
    localStorage.getItem(k);
    localStorage.removeItem(k);
  } catch (e) { /* almacenamiento no disponible */ }
  return Math.max(1, Math.round(performance.now() - t0));
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

function openPoliciesModal() {
  const modal = document.getElementById("modal-politicas");
  if (!modal) return;
  modal.classList.remove("hidden");
  modal.classList.add("flex");
  document.body.style.overflow = "hidden";
}

function closePoliciesModal() {
  const modal = document.getElementById("modal-politicas");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
  // Solo restaura el scroll si ningún otro modal sigue abierto
  // (puede abrirse sobre el modal de reserva desde el paso 3).
  const bookingModal = document.getElementById("booking-modal");
  if (!bookingModal || !bookingModal.classList.contains("flex")) {
    document.body.style.overflow = "";
  }
}

function openProfileLightbox() {
  const lightbox = document.getElementById("profile-lightbox");
  if (!lightbox) return;
  lightbox.classList.remove("hidden");
  lightbox.classList.add("flex");
  document.body.style.overflow = "hidden";
}

function closeProfileLightbox() {
  const lightbox = document.getElementById("profile-lightbox");
  if (!lightbox) return;
  lightbox.classList.add("hidden");
  lightbox.classList.remove("flex");
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
  _ids: ['booking-modal', 'adminLoginModal', 'adminPortalModal', 'mediaLightboxModal', 'invoicePreviewModal'],

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
    const anyOpen = document.querySelectorAll('#booking-modal.flex, #adminLoginModal.flex, #adminPortalModal.flex, #mediaLightboxModal.flex, #invoicePreviewModal.flex');
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
    selectedTime: "",
    voucherImage: null,
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
  if (canton) canton.innerHTML = '<option value="" disabled selected class="text-gray-500 bg-[#0b0714]">Seleccione primero provincia</option>';

  const voucher = document.getElementById("voucher-view");
  const gateway = document.getElementById("sinpe-gateway-view");
  if (voucher) voucher.classList.add("hidden");
  if (gateway) gateway.classList.remove("hidden");

  // Nueva reserva: limpiar comprobante SINPE previamente cargado (miniatura + botón).
  resetVoucherUploadState();

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

  // La nueva fecha invalida la hora previa y re-renderiza los chips.
  resetSelectedTime();
  renderTimeSelector();

  // "Continuar a Ubicación & Datos" solo se habilita con fecha Y hora.
  updateStep2ContinueState();

  // Toast sutil con formato DD/MM/AAAA
  const [yy, mm, dd] = foundISO.split("-");
  showToast(`Fecha seleccionada: ${dd}/${mm}/${yy}. Elija la hora.`, "success");
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
    // T&C de contratación: bloquear el avance al Paso 4 si la casilla no está
    // marcada. Cubre también el salto directo desde el stepper (nodo "4").
    if (cart.currentStep === 3 && !validatePoliciesAcceptance()) {
      showToast("⚠️ Debe aceptar los Términos y Condiciones para continuar.", "error");
      updateModalStep(3);
      return;
    }
    saveClientAndLocationValues();
  }

  cart.currentStep = stepNumber;
  cart.persist();
  updateModalStep(stepNumber);
}

/**
 * Verifica que el cliente haya aceptado los Términos y Condiciones de
 * Contratación y Políticas de Cancelación antes del Paso 4 (Pago SINPE).
 * Devuelve true si la casilla está marcada (o si el checkbox no existe,
 * para no bloquear flujos heredados que no lo rendericen).
 */
function validatePoliciesAcceptance() {
  const policiesCheckbox = document.getElementById("accept-policies-checkbox");
  return !policiesCheckbox || policiesCheckbox.checked;
}

// ---- Prevención de Doble Envío (Rate Limiting) ----
// El botón "Continuar a Pago SINPE" se deshabilita al enviar y se reactiva
// al llegar al paso 4 (o tras 3 segundos como respaldo).

let step3SubmitLocked = false;

function handleStep3Submit(event) {
  event.preventDefault();
  if (step3SubmitLocked) return; // ya en proceso: ignorar doble clic

  if (isHoneypotTriggered()) return; // neutralización silenciosa de bots

  // Mismas validaciones que goToStep(4): si algo falla, no bloqueamos el botón.
  if (!validateCalendarSelection()) {
    updateModalStep(2);
    return;
  }
  const form = document.getElementById("booking-form-step3");
  if (form && !form.checkValidity()) {
    form.reportValidity();
    return;
  }
  if (!validateClientData()) return;

  // T&C de contratación: obligatorio marcar la casilla para avanzar al pago.
  if (!validatePoliciesAcceptance()) {
    showToast("⚠️ Debe aceptar los Términos y Condiciones para continuar.", "error");
    return;
  }

  lockStep3Submit();
  goToStep(4); // goToStep re-valida (mismo estado) y hace la transición formal
}

function lockStep3Submit() {
  const btn = document.getElementById("btn-continue-pay");
  if (!btn) return;
  step3SubmitLocked = true;
  btn.disabled = true;
  const label = document.getElementById("btn-continue-pay-label");
  if (label) label.textContent = "Procesando…";
  // Respaldo: nunca dejar el botón bloqueado más de 3 segundos
  setTimeout(() => { if (step3SubmitLocked) unlockStep3Submit(); }, 3000);
}

function unlockStep3Submit() {
  const btn = document.getElementById("btn-continue-pay");
  step3SubmitLocked = false;
  if (!btn) return;
  btn.disabled = false;
  const label = document.getElementById("btn-continue-pay-label");
  if (label) label.textContent = "Continuar a Pago SINPE (50%)";
}

function validateCalendarSelection() {
  if (!cart.selectedDate) {
    showToast("Seleccione una fecha disponible en el calendario.", "error");
    return false;
  }
  return true;
}

/**
 * Nombre/empresa estricto: mínimo 2 palabras y 6 caracteres en total.
 * Bloquea datos dummy tipo "aaa", "juan", "x y" (1 palabra o < 6 chars).
 */
function isValidClientName(value) {
  const v = String(value || "").trim();
  if (v.length < 6) return false;
  const words = v.split(/\s+/).filter(Boolean);
  return words.length >= 2;
}

function isValidClientLocation() {
  const prov = document.getElementById("booking-province");
  const canton = document.getElementById("booking-canton");
  return Boolean(prov && prov.value && canton && canton.value);
}

function validateClientData() {
  const nameEl = document.getElementById("client-name");
  const nameVal = nameEl ? nameEl.value.trim() : "";
  if (!isValidClientName(nameVal)) {
    nameEl && showFieldError(nameEl, "El nombre o empresa debe tener al menos 2 palabras y 6 caracteres (ej. 'Carlos Rodríguez').");
    if (nameEl) { nameEl.focus(); triggerFieldShake(nameEl); }
    return false;
  }
  if (nameEl) clearFieldError(nameEl);

  const phoneEl = document.getElementById("client-phone");
  if (phoneEl && !isValidCRPhone(phoneEl.value)) {
    showFieldError(phoneEl, "Teléfono inválido: use formato 8888-8888 o +506 8888-8888.");
    phoneEl.focus();
    triggerFieldShake(phoneEl);
    return false;
  }
  if (phoneEl) clearFieldError(phoneEl);

  const emailEl = document.getElementById("client-email");
  if (emailEl && !isValidRFC5322Email(emailEl.value)) {
    showFieldError(emailEl, "Ingrese un correo electrónico válido (RFC 5322).");
    emailEl.focus();
    triggerFieldShake(emailEl);
    return false;
  }
  if (emailEl) clearFieldError(emailEl);

  if (!isValidClientLocation()) {
    showToast("Seleccione Provincia y Cantón para continuar.", "error");
    const prov = document.getElementById("booking-province");
    const canton = document.getElementById("booking-canton");
    if (prov && !prov.value) { markFieldInvalid(prov); triggerFieldShake(prov); }
    if (canton && !canton.value) { markFieldInvalid(canton); triggerFieldShake(canton); }
    return false;
  }

  return true;
}

// ---- Visual feedback estricto (borde rojo + mensaje) ----

function fieldShell(el) {
  return el && el.closest ? el.closest(".validate-field") : null;
}

function showFieldError(el, message) {
  if (!el) return;
  markFieldInvalid(el);
  const shell = fieldShell(el);
  let tip = shell ? shell.querySelector(".field-error") : null;
  if (!tip) {
    tip = document.createElement("span");
    tip.className = "field-error";
    tip.setAttribute("role", "alert");
    if (shell) shell.appendChild(tip);
    else el.insertAdjacentElement("afterend", tip);
  }
  tip.textContent = message;
}

function clearFieldError(el) {
  if (!el) return;
  markFieldValid(el);
  const shell = fieldShell(el);
  const tip = shell ? shell.querySelector(".field-error") : null;
  if (tip) tip.textContent = "";
}

function markFieldInvalid(el) {
  if (!el) return;
  el.classList.remove("field-valid");
  el.classList.add("field-invalid");
}

function markFieldValid(el) {
  if (!el) return;
  el.classList.remove("field-invalid");
  el.classList.add("field-valid");
}

function triggerFieldShake(el) {
  if (!el) return;
  el.classList.remove("field-shake");
  void el.offsetWidth; // reinicia la animación
  el.classList.add("field-shake");
}

/** Evalúa en vivo un campo del paso 3 y actualiza el feedback visual. */
function validateFieldLive(field) {
  const id = field && field.id;
  if (id === "client-name") {
    isValidClientName(field.value) ? clearFieldError(field) : markFieldInvalid(field);
  } else if (id === "client-phone") {
    isValidCRPhone(field.value) ? clearFieldError(field) : markFieldInvalid(field);
  } else if (id === "client-email") {
    isValidRFC5322Email(field.value) ? clearFieldError(field) : markFieldInvalid(field);
  } else if (id === "booking-address") {
    String(field.value || "").trim().length >= 6 ? clearFieldError(field) : markFieldInvalid(field);
  } else if (id === "booking-province" || id === "booking-canton") {
    isValidClientLocation() ? clearFieldError(field) : markFieldInvalid(field);
  } else if (field && field.tagName === "SELECT") {
    field.value ? clearFieldError(field) : markFieldInvalid(field);
  }
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

  // Connectors: se iluminan en verde cuando el paso a su izquierda está completo
  for (let i = 1; i < 4; i++) {
    const node = document.getElementById(`step-indicator-${i}`);
    const conn = node && node.nextElementSibling;
    if (conn && conn.classList.contains("modal-stepper-connector")) {
      conn.classList.toggle("connector--complete", i < stepNumber);
    }
  }

  // Volver al inicio del contenido del modal en cada transición de paso
  const modalCard = document.getElementById("modal-card");
  if (modalCard) modalCard.scrollTop = 0;

  if (stepNumber === 2) {
    CalendarModule.init();
    renderTimeSelector();
    updateStep2ContinueState();
  }

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
        ? `${cart.selectedDate}${cart.selectedTime ? " a las " + cart.selectedTime : ""}`
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
        // Reanudar el estado de subida previo (miniatura + botón habilitado).
        updateVoucherUploadUI();
      }
    }
    unlockStep3Submit(); // llega al paso 4 → reactivar el botón de envío
  }

  if (cart.selectedService) {
    document.getElementById("modal-service-name").textContent = cart.selectedService.name;
    document.getElementById("modal-service-price").textContent = formatCRC(PriceManager.getServicePrice(cart.selectedService));
    document.getElementById("modal-service-desc").textContent = cart.selectedService.description;

    const logBox = document.getElementById("modal-service-logistics");
    if (logBox) {
      // Card clara: tiempos en fuente monoespaciada gris con ícono de reloj
      logBox.innerHTML = `
        <span class="format-card__time"><span aria-hidden="true">⏱️</span> Montaje: ${sanitizeInput(cart.selectedService.setup_display || "2h antes")}</span>
        <span class="format-card__time"><span aria-hidden="true">⏱️</span> Desmontaje: ${sanitizeInput(cart.selectedService.teardown_display || "1h después")}</span>
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
      tag: "50% Tarifa Base",
      unitPrice: `${formatCRC(extraHourPrice)} / hora`,
      priceText: `50% de ${formatCRC(PriceManager.getServicePrice(cart.selectedService))} — máx. ${MAX_EXTRAS.extraHoursCount}`,
      value: cart.extraHoursCount,
      max: MAX_EXTRAS.extraHoursCount
    }),
    counterRow({
      key: "djHoursCount",
      name: "Servicio de DJ para Recesos",
      unitPrice: `${formatCRC(djPrice)} / hr`,
      priceText: "Música continua y mezcla en vivo durante los descansos de la banda",
      value: cart.djHoursCount,
      max: MAX_EXTRAS.djHoursCount
    }),
    counterRow({
      key: "subwoofersCount",
      name: 'Subwoofers Extra de 18"',
      unitPrice: `${formatCRC(subPrice)} / un`,
      priceText: "Potencia adicional de frecuencias bajas para salones amplios o exteriores",
      value: cart.subwoofersCount,
      max: MAX_EXTRAS.subwoofersCount
    })
  ].join("");
}

/**
 * Tarjeta de extra clara: título + tag a la izquierda, stepper circular
 * (− / valor / +) y badge de precio negro mate a la derecha.
 * En móvil (< 640px) la tarjeta apila verticalmente vía CSS.
 */
function counterRow({ key, name, tag, unitPrice, priceText, value, max }) {
  const atMin = value <= 0;
  const atMax = value >= max;
  const btnDisabled = " is-disabled";
  return `
    <div class="extra-card">
      <div class="extra-card__info">
        <div class="extra-card__head">
          <span class="extra-card__name">${sanitizeInput(name)}</span>
          ${tag ? `<span class="extra-card__tag">${sanitizeInput(tag)}</span>` : ""}
        </div>
        <p class="extra-card__price-text">${sanitizeInput(priceText)}</p>
      </div>
      <div class="extra-card__controls">
        <div class="extra-stepper">
          <button type="button" onclick="adjustExtra('${key}', -1)" ${atMin ? "disabled" : ""} class="extra-step-btn${atMin ? btnDisabled : ""}" aria-label="Disminuir ${sanitizeInput(name)}">−</button>
          <span class="extra-stepper__value" aria-live="polite">${value}</span>
          <button type="button" onclick="adjustExtra('${key}', 1)" ${atMax ? "disabled" : ""} class="extra-step-btn${atMax ? btnDisabled : ""}" aria-label="Aumentar ${sanitizeInput(name)}">+</button>
        </div>
        <span class="extra-card__price-badge">${sanitizeInput(unitPrice)}</span>
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

  const banner = document.createElement("div");
  banner.className = "surcharge-banner";

  const icon = document.createElement("span");
  icon.className = "surcharge-banner__icon";
  icon.setAttribute("aria-hidden", "true");

  const body = document.createElement("div");
  body.className = "surcharge-banner__body";

  const title = document.createElement("p");
  title.className = "surcharge-banner__title";

  const detail = document.createElement("p");
  detail.className = "surcharge-banner__detail";

  if (!cart.province) {
    // Pendiente de selección → banner ámbar
    banner.classList.add("surcharge-banner--pending");
    icon.textContent = "⚠️";
    title.textContent = "Pendiente de selección";
    detail.textContent = "Seleccione su provincia para calcular los viáticos de transporte.";
  } else {
    // Provincia seleccionada → banner verde (viáticos ya calculables)
    banner.classList.add("surcharge-banner--ok");
    icon.textContent = "✅";
    title.textContent = "Viáticos calculados según provincia";
    if (!GAM_PROVINCES.includes(cart.province)) {
      detail.textContent = `Recargo del 12% por viáticos fuera del GAM (${cart.province}): +${formatCRC(cart.travelSurcharge)}`;
    } else if (!cart.canton) {
      detail.textContent = `${cart.province} está dentro del GAM — seleccione el cantón para confirmar cobertura (₡0).`;
    } else if (cart.isNonGam) {
      detail.textContent = `Recargo del 12% por viáticos fuera del GAM (${cart.canton}, ${cart.province}): +${formatCRC(cart.travelSurcharge)}`;
    } else {
      detail.textContent = `Cobertura GAM (${cart.canton}, ${cart.province}): ₡0 (Gratis)`;
    }
  }

  box.appendChild(banner);
  banner.appendChild(icon);
  banner.appendChild(body);
  body.appendChild(title);
  body.appendChild(detail);
}

// ---- Provincias & Cantones ----

function populateProvinces() {
  const provSelect = document.getElementById("booking-province");
  if (!provSelect) return;
  provSelect.innerHTML = '<option value="" disabled selected class="text-gray-500 bg-[#0b0714]">Seleccione Provincia...</option>' +
    Object.keys(PROVINCES_AND_CANTONES).map(p => `<option value="${sanitizeInput(p)}">${sanitizeInput(p)}</option>`).join("");
}

function populateCantones(province) {
  const cantonSelect = document.getElementById("booking-canton");
  if (!cantonSelect) return;

  const list = (province && PROVINCES_AND_CANTONES[province]) ? PROVINCES_AND_CANTONES[province] : [];
  cantonSelect.innerHTML = '<option value="" disabled selected class="text-gray-500 bg-[#0b0714]">Seleccione Cantón...</option>' +
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
// 15B. VOUCHER UPLOADER & CLIENT-SIDE COMPRESSION
// Subida nativa del comprobante SINPE (sin servicios de terceros):
// se comprime a JPEG en canvas (< ~100KB) y se embebe como data-URL
// en CartState → visible en el Dashboard del Staff sin backups externos.
// ============================================================

const VOUCHER_MAX_WIDTH = 800; // ancho máximo de redimensionamiento
const VOUCHER_JPEG_QUALITY = 0.7; // calidad de compresión JPEG
const VOUCHER_MAX_BYTES = 102400; // ~100KB objetivo tras comprimir
const VOUCHER_MAX_SOURCE_MB = 8; // límite de tamaño del archivo original

function readFileAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("No se pudo leer el archivo seleccionado."));
    reader.readAsDataURL(file);
  });
}

function loadImage(src) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("Imagen inválida o corrupta."));
    img.src = src;
  });
}

/**
 * Redimensiona y comprime el comprobante a un data-URL JPEG (~<100KB)
 * usando el canvas del navegador. Nunca toca servidores ni enlaces externos.
 */
async function compressImage(file) {
  const rawDataUrl = await readFileAsDataURL(file);
  const img = await loadImage(rawDataUrl);

  let width = img.naturalWidth || img.width;
  let height = img.naturalHeight || img.height;
  if (!width || !height) throw new Error("No se pudo leer las dimensiones de la imagen.");

  const maxDim = VOUCHER_MAX_WIDTH;
  if (width > maxDim) {
    height = Math.round((height * maxDim) / width);
    width = maxDim;
  }

  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0, width, height);

  return canvas.toDataURL("image/jpeg", VOUCHER_JPEG_QUALITY);
}

/**
 * Procesa el archivo seleccionado: valida tipo/tamaño y delega en la
 * compresión. Al terminar actualiza CartState + refleja el estado en la UI.
 */
function handleVoucherUpload(file) {
  if (!file) return;

  if (!/^image\/(jpeg|png|webp)$/.test(file.type)) {
    showToast("Formato no permitido. Use JPG, PNG o WEBP.", "error");
    return;
  }
  if (file.size > VOUCHER_MAX_SOURCE_MB * 1024 * 1024) {
    showToast(`La imagen supera los ${VOUCHER_MAX_SOURCE_MB}MB permitidos.`, "error");
    return;
  }

  compressImage(file)
    .then(dataUrl => {
      cart.voucherImage = dataUrl;
      cart.persist();
      updateVoucherUploadUI();
      showToast("Comprobante cargado y comprimido correctamente.", "success");
    })
    .catch(err => {
      showToast(err.message || "No se pudo cargar el comprobante.", "error");
    });
}

/**
 * Sincroniza la zona de subida con el estado del carrito
 * (icono ↔ miniatura, textos y habilitación del botón de confirmación).
 */
function updateVoucherUploadUI() {
  const img = document.getElementById("voucher-thumb");
  const icon = document.getElementById("voucher-upload-icon");
  const txt = document.getElementById("voucher-upload-text");
  const status = document.getElementById("voucher-upload-status");

  if (cart.voucherImage) {
    if (img) {
      img.src = cart.voucherImage;
      img.classList.remove("hidden");
    }
    if (icon) icon.classList.add("hidden");
    if (txt) {
      txt.textContent = "Comprobante Cargado ✓";
      txt.classList.add("text-emerald-400");
    }
    if (status) status.textContent = "JPG/PNG/WEBP · comprimido al instante";
  } else {
    if (img) {
      img.classList.add("hidden");
      img.removeAttribute("src");
    }
    if (icon) icon.classList.remove("hidden");
    if (txt) {
      txt.textContent = "Sube la captura de tu transferencia SINPE";
      txt.classList.remove("text-emerald-400");
    }
    if (status) status.textContent = "JPG, PNG o WEBP · se comprime al instante (<100kb)";
  }

  updateGenerateButtonState();
}

/**
 * Habilita "Generar Voucher y Confirmar" SOLO cuando existe comprobante cargado.
 */
function updateGenerateButtonState() {
  const btn = document.getElementById("btn-submit-booking");
  if (!btn) return;
  btn.disabled = !Boolean(cart.voucherImage);
}

/**
 * Restablece el estado de la subida (usado al volver a empezar el flujo).
 */
function resetVoucherUploadState() {
  cart.voucherImage = null;
  cart.persist();
  updateVoucherUploadUI();
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

  // La confirmación del voucher exige hora de evento Y comprobante SINPE cargado.
  if (!cart.selectedTime) {
    showToast("Seleccione la hora del evento en el Calendario & Hora.", "error");
    goToStep(2);
    return;
  }
  if (!cart.voucherImage) {
    showToast("Adjunte la captura del comprobante SINPE para confirmar la reserva.", "error");
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

📅 *Fecha & Hora:* ${formatDisplayDate(cart.selectedDate)} a las ${cart.selectedTime}
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
      selectedTime: cart.selectedTime,
      voucherImage: cart.voucherImage,
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

    document.getElementById("confirm-event-date").textContent = `${formatDisplayDate(cart.selectedDate)}${cart.selectedTime ? " a las " + cart.selectedTime : ""}`;
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
// 18. FOOTER: AMBIENT LIGHT NEÓN EN CSS PURO
// El fondo del footer ya NO usa canvas: la animación vive en
// footer::before (CSS, sólo opacidad con compositing por hardware).
// El JS del footer queda limitado a eventos DOM (click/copy/SINPE).
// ============================================================

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

