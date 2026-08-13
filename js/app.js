// Arkik Productions - Elite State Management & Reactive UI Engine (v2 - Phase 0 Hardened)

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
    this.eventDate = "";
    this.eventTime = "";
    this.address = "";
    this.sinpeRef = "";
    this.createdBooking = null;
    this.currentStep = 1;
    this.isSubmitting = false;
    this.restore();
  }

  // ---- Pricing Engine (pure money math, integer colones) ----

  // Extra Hours Cost (50% of selected service base price per hour)
  get extraHoursUnitPrice() {
    if (!this.selectedService) return 0;
    return Math.round(this.selectedService.price_crc * 0.50);
  }

  get extraHoursTotal() {
    return this.extraHoursUnitPrice * this.extraHoursCount;
  }

  // DJ Service Cost (₡75,000 per hour)
  get djTotal() {
    return DYNAMIC_EXTRAS_CONFIG.dj_service.unitPrice * this.djHoursCount;
  }

  // Subwoofers Cost (₡80,000 per unit)
  get subwoofersTotal() {
    return DYNAMIC_EXTRAS_CONFIG.subwoofers.unitPrice * this.subwoofersCount;
  }

  // Subtotal (Service + Extras)
  get subtotal() {
    const base = this.selectedService ? this.selectedService.price_crc : 0;
    return base + this.extraHoursTotal + this.djTotal + this.subwoofersTotal;
  }

  // GAM is validated by Province AND Canton (canton-level exceptions)
  get isNonGam() {
    if (!this.province) return false;
    if (!GAM_PROVINCES.includes(this.province)) return true;
    if (!this.canton) return false;
    return (NON_GAM_EXCEPTIONS[this.province] || []).includes(this.canton);
  }

  get locationKnown() {
    return Boolean(this.province && this.canton);
  }

  // Non-GAM travel surcharge (12%)
  get travelSurcharge() {
    return this.isNonGam ? Math.round(this.subtotal * NON_GAM_SURCHARGE_RATE) : 0;
  }

  // Gran Total
  get granTotal() {
    return this.subtotal + this.travelSurcharge;
  }

  // 50% SINPE Deposit Amount
  get deposit50Amount() {
    return Math.round(this.granTotal * SINPE_CONFIG.depositPercentage);
  }

  // 50% Remaining balance on event day
  get remainingBalance() {
    return this.granTotal - this.deposit50Amount;
  }

  // ---- Persistence (localStorage recovery across refresh) ----

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
      eventDate: this.eventDate,
      eventTime: this.eventTime,
      address: this.address,
      sinpeRef: this.sinpeRef
    };
  }

  persist() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.serialize()));
    } catch (err) {
      // Storage unavailable (private mode / blocked): non-fatal
    }
  }

  restore() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const data = JSON.parse(raw);
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
      this.eventDate = cleanText(data.eventDate, 10);
      this.eventTime = cleanText(data.eventTime, 5);
      this.address = cleanText(data.address, 300);
      this.sinpeRef = cleanText(data.sinpeRef, 50);
    } catch (err) {
      // Corrupt payload: fall through with defaults
    }
  }

  clearStoredState() {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (err) {
      // ignore
    }
  }
}

// ---- Pure Helpers ----

function clampInt(value, min, max) {
  const n = parseInt(value, 10);
  if (Number.isNaN(n)) return min;
  return Math.min(max, Math.max(min, n));
}

function cleanText(value, maxLen) {
  return typeof value === "string" ? value.trim().slice(0, maxLen) : "";
}

function isValidCRPhone(phone) {
  return /^(?:\+?506[\s-]?)?[2-8]\d{3}[\s-]?\d{4}$/.test(phone.trim());
}

function generateBookingCode() {
  let hex = "";
  try {
    hex = crypto.randomUUID().replace(/-/g, "");
  } catch (err) {
    hex = Date.now().toString(16) + Math.random().toString(16).slice(2, 10);
  }
  return `ARK-${hex.slice(0, 8).toUpperCase()}`;
}

function setMinBookingDate() {
  const el = document.getElementById("booking-date");
  if (!el) return;
  const today = new Date();
  const iso = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`;
  el.min = iso;
}

function setField(id, value) {
  const el = document.getElementById(id);
  if (el && value) el.value = value;
}

// Global App Instance
const cart = new CartState();

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

function initApp() {
  renderCatalog(CATALOG_SERVICES);
  renderGalleryFilters();
  renderMediaGallery(mediaLibrary, 'todos');
  setupEventListeners();
  populateProvinces();
  setMinBookingDate();
  restoreBookingToUI();
}

// Render Services Catalog Cards
function renderCatalog(services, category = 'Todos') {
  const container = document.getElementById('catalog-grid');
  if (!container) return;

  const filtered = category === 'Todos'
    ? services
    : services.filter(s => s.category === category);

  container.innerHTML = filtered.map(service => `
    <div class="glass-panel rounded-2xl overflow-hidden flex flex-col justify-between group transform hover:-translate-y-2 transition-all duration-300 relative">
      ${service.badge ? `
        <span class="absolute top-4 right-4 z-10 bg-gradient-to-r from-purple-600 to-pink-600 text-white text-xs font-bold px-3 py-1 rounded-full shadow-lg">
          ${service.badge}
        </span>
      ` : ''}

      <div>
        <div class="relative h-56 overflow-hidden">
          <img src="${service.image_url}" alt="${service.name}" class="w-full h-full object-cover group-hover:scale-110 transition-transform duration-300" />
          <div class="absolute inset-0 bg-gradient-to-t from-[#0b0914] via-transparent to-transparent"></div>
          <span class="absolute bottom-3 left-4 text-xs font-semibold px-2.5 py-1 rounded-md bg-purple-950/80 border border-purple-500/40 text-purple-300">
            ${service.category}
          </span>
        </div>

        <div class="p-6">
          <h3 class="text-xl font-bold text-white group-hover:text-purple-300 transition-colors">${service.name}</h3>
          <p class="text-sm text-gray-400 mt-2 line-clamp-3 leading-relaxed">${service.description}</p>

          <div class="mt-4 pt-4 border-t border-purple-500/20 space-y-2">
            <div class="flex items-center text-xs text-purple-300 font-medium">
              <svg class="w-4 h-4 mr-2 text-pink-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
              ${service.duration}
            </div>
            <div class="flex items-start text-xs text-gray-400">
              <svg class="w-4 h-4 mr-2 text-purple-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
              <span>${service.tech_specs}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="p-6 pt-0">
        <div class="flex items-baseline justify-between mb-4">
          <span class="text-xs text-gray-400 font-medium">Tarifa Base (2 hrs)</span>
          <span class="text-2xl font-extrabold text-gradient-purple">₡${service.price_crc.toLocaleString('es-CR')}</span>
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

// Render interactive filter buttons from GALLERY_FILTERS (data.js)
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
    return `<button type="button" data-filter="${filter.key}" class="${base}${state}">${filter.label} <span class="opacity-60 font-semibold">(${count})</span></button>`;
  }).join('');
}

// Render gallery cards filtered by category ('todos' | banda | acustico | tecnico)
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
      ${label}
    </span>
  `;
}

function galleryCardShell(item, mediaHtml) {
  return `
    <article class="gallery-card group relative rounded-2xl overflow-hidden border border-white/10 bg-white/5 backdrop-blur-xl transition-all duration-300 hover:scale-[1.02] hover:border-purple-500/50 hover:shadow-[0_8px_40px_rgba(168,85,247,0.25)]">
      ${mediaHtml}
      <div class="p-5">
        <h4 class="text-sm font-bold text-white group-hover:text-purple-300 transition-colors leading-snug">${item.title}</h4>
        ${item.subtitle ? `<p class="text-xs text-gray-400 mt-1">${item.subtitle}</p>` : ''}
      </div>
    </article>
  `;
}

function galleryVideoCard(item) {
  const media = `
    <div id="gallery-media-${item.id}" class="relative aspect-video overflow-hidden">
      <img src="${item.thumbnail}" alt="${item.title}" loading="lazy"
        class="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110" />
      <div class="absolute inset-0 bg-gradient-to-t from-[#0a0712] via-[#0a0712]/25 to-transparent"></div>
      ${galleryCategoryBadge(item)}
      <button type="button" onclick="playGalleryVideo(${item.id})" aria-label="Reproducir video: ${item.title}"
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
      <img src="${item.url}" alt="${item.title}" loading="lazy"
        class="w-full h-full object-cover transition-transform duration-700 group-hover:scale-110" />
      <div class="absolute inset-0 bg-gradient-to-t from-[#0a0712]/80 via-transparent to-transparent"></div>
      ${galleryCategoryBadge(item)}
    </div>
  `;
  return galleryCardShell(item, media);
}

// Lazy-load YouTube video on demand (no iframes until the play button is pressed)
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

// Setup Event Listeners
function setupEventListeners() {
  // Category Filter Tabs
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

  // Gallery filter buttons (event delegation: buttons are re-rendered dynamically)
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

  // Province change -> Populate Cantones, reset canton & recalc Non-GAM surcharge
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

  // Canton change -> Keep state in sync & recalc Non-GAM surcharge (canton-level GAM)
  const cantonSelect = document.getElementById('booking-canton');
  if (cantonSelect) {
    cantonSelect.addEventListener('change', (e) => {
      cart.canton = e.target.value;
      updateSummaryPrices();
      cart.persist();
    });
  }

  // ESC closes the executive card, brand presentation and/or booking modal
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
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
  });
}

// ---- Executive Card Lightbox (Tarjeta Ejecutiva VIP) ----

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

// ---- Brand Presentation Modal (Presentación de Marca VIP) ----

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

// Modal Control
function openBookingModal(serviceId) {
  resetBooking();

  cart.selectedService = CATALOG_SERVICES.find(s => s.id === serviceId) || CATALOG_SERVICES[0];
  cart.persist();

  setMinBookingDate();
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

// Fresh cart + empty Step 2 DOM every time the modal opens or closes
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
    eventDate: "",
    eventTime: "",
    address: "",
    sinpeRef: "",
    createdBooking: null,
    currentStep: 1,
    isSubmitting: false
  });

  const ids = ['client-name', 'client-phone', 'client-email', 'booking-date', 'booking-time', 'booking-address', 'sinpe-reference'];
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

  cart.clearStoredState();
}

// Step Navigation
function goToStep(stepNumber) {
  // Unconditional validation when entering Step 3 (SINPE gateway)
  if (stepNumber === 3) {
    const form = document.getElementById('booking-form-step2');
    if (form && !form.checkValidity()) {
      form.reportValidity();
      return;
    }
    if (!validateBookingDateTime()) return;
    if (!validateClientPhone()) return;
    saveStep2Values();
  }

  cart.currentStep = stepNumber;
  cart.persist();
  updateModalStep(stepNumber);
}

function saveStep2Values() {
  cart.clientName = document.getElementById('client-name').value.trim();
  cart.clientPhone = document.getElementById('client-phone').value.trim();
  cart.clientEmail = document.getElementById('client-email').value.trim();
  cart.eventType = document.getElementById('event-type').value;
  cart.eventDate = document.getElementById('booking-date').value;
  cart.eventTime = document.getElementById('booking-time').value;
  cart.canton = document.getElementById('booking-canton').value;
  cart.address = document.getElementById('booking-address').value.trim();
}

// Strict date & time validation: block past dates and past times on today
function validateBookingDateTime() {
  const dateEl = document.getElementById('booking-date');
  const timeEl = document.getElementById('booking-time');
  const dateVal = dateEl.value;
  const timeVal = timeEl.value;

  if (!dateVal || !timeVal) {
    showToast('La fecha y la hora del evento son obligatorias.', 'error');
    (dateEl.value ? timeEl : dateEl).focus();
    return false;
  }

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const [y, m, d] = dateVal.split('-').map(Number);
  const selectedDate = new Date(y, m - 1, d);

  if (selectedDate < today) {
    showToast('La fecha del evento no puede estar en el pasado.', 'error');
    dateEl.focus();
    return false;
  }

  if (selectedDate.getTime() === today.getTime()) {
    const [hh, mm] = timeVal.split(':').map(Number);
    const now = new Date();
    if (hh < now.getHours() || (hh === now.getHours() && mm <= now.getMinutes())) {
      showToast('La hora del evento debe ser futura para el día de hoy.', 'error');
      timeEl.focus();
      return false;
    }
  }

  return true;
}

// CR phone validation (+506, 8 digits, landline/mobile ranges)
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

function updateModalStep(stepNumber) {
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
      } else {
        stepPane.classList.add('hidden');
      }
    }
  }

  if (cart.selectedService) {
    document.getElementById('modal-service-name').textContent = cart.selectedService.name;
    document.getElementById('modal-service-price').textContent = `₡${cart.selectedService.price_crc.toLocaleString('es-CR')}`;
    document.getElementById('modal-service-desc').textContent = cart.selectedService.description;

    renderDynamicExtrasCounters();
    updateSummaryPrices();
  }
}

// Render Counters for Extras (Hora Extra 50%, DJ ₡75k, Subwoofers ₡80k) with hard caps
function renderDynamicExtrasCounters() {
  const container = document.getElementById('extras-container');
  if (!container) return;

  const extraHourPrice = cart.extraHoursUnitPrice;

  container.innerHTML = [
    counterRow({
      key: 'extraHoursCount',
      name: 'Hora(s) Adicional(es) de Show',
      badge: '50% del Base',
      badgeClass: 'bg-purple-900/60 text-purple-300 border border-purple-500/40',
      priceText: `₡${extraHourPrice.toLocaleString('es-CR')} por hora adicional (50% de ₡${cart.selectedService.price_crc.toLocaleString('es-CR')}) — máx. ${MAX_EXTRAS.extraHoursCount}`,
      value: cart.extraHoursCount,
      max: MAX_EXTRAS.extraHoursCount
    }),
    counterRow({
      key: 'djHoursCount',
      name: 'Servicio de DJ para Recesos',
      badge: '₡75,000 / hr',
      badgeClass: 'text-pink-400',
      priceText: 'Música continua y mezcla en vivo durante descansos',
      value: cart.djHoursCount,
      max: MAX_EXTRAS.djHoursCount
    }),
    counterRow({
      key: 'subwoofersCount',
      name: 'Subwoofers Extra de 18"',
      badge: '₡80,000 / un',
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
          <span class="text-sm font-bold text-white">${name}</span>
          <span class="text-[10px] font-extrabold px-2 py-0.5 rounded ${badgeClass}">${badge}</span>
        </div>
        <p class="text-xs text-gray-400 mt-0.5">${priceText}</p>
      </div>
      <div class="flex items-center space-x-3">
        <button type="button" onclick="adjustExtra('${key}', -1)" ${atMin ? "disabled" : ""} class="${btnBase}${atMin ? btnDisabled : ""}">-</button>
        <span class="text-base font-extrabold text-white w-6 text-center">${value}</span>
        <button type="button" onclick="adjustExtra('${key}', 1)" ${atMax ? "disabled" : ""} class="${btnBase}${atMax ? btnDisabled : ""}">+</button>
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

// Update all summary price displays reactively
function updateSummaryPrices() {
  document.querySelectorAll('.calc-subtotal').forEach(el => {
    el.textContent = `₡${cart.subtotal.toLocaleString('es-CR')}`;
  });

  document.querySelectorAll('.calc-gran-total').forEach(el => {
    el.textContent = `₡${cart.granTotal.toLocaleString('es-CR')}`;
  });

  document.querySelectorAll('.calc-deposit-50').forEach(el => {
    el.textContent = `₡${cart.deposit50Amount.toLocaleString('es-CR')}`;
  });

  document.querySelectorAll('.calc-remaining-50').forEach(el => {
    el.textContent = `₡${cart.remainingBalance.toLocaleString('es-CR')}`;
  });

  updateSurchargeBox();
}

// Travel surcharge notice: honest states (never claims GAM coverage without a province)
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

// Populate Province & Canton dropdowns
function populateProvinces() {
  const provSelect = document.getElementById('booking-province');
  if (!provSelect) return;
  provSelect.innerHTML = '<option value="">Seleccione Provincia...</option>' +
    Object.keys(PROVINCES_AND_CANTONES).map(p => `<option value="${p}">${p}</option>`).join('');
}

function populateCantones(province) {
  const cantonSelect = document.getElementById('booking-canton');
  if (!cantonSelect) return;

  const list = (province && PROVINCES_AND_CANTONES[province]) ? PROVINCES_AND_CANTONES[province] : [];
  cantonSelect.innerHTML = '<option value="">Seleccione Cantón...</option>' +
    list.map(c => `<option value="${c}">${c}</option>`).join('');
}

// Restore a recovered (refreshed) cart back into the Step 2 DOM
function restoreBookingToUI() {
  if (!cart.province && !cart.canton && !cart.eventDate && !cart.clientName) return;

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
  setField('booking-date', cart.eventDate);
  setField('booking-time', cart.eventTime);
  setField('booking-address', cart.address);
  setField('sinpe-reference', cart.sinpeRef);

  updateSummaryPrices();
}

// Finalize Static Booking & Generate WhatsApp URL Breakdown
function submitStaticBooking() {
  if (cart.isSubmitting) return;

  // Defense in depth: never generate a voucher from an incomplete quote
  if (!cart.clientName || !cart.clientPhone || !cart.eventDate || !cart.eventTime || !cart.province || !cart.canton) {
    showToast('Faltan datos obligatorios del evento. Complete el paso de ubicación.', 'error');
    goToStep(2);
    return;
  }

  const btn = document.getElementById('btn-submit-booking');
  const originalLabel = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = 'Generando voucher…';
  }
  cart.isSubmitting = true;

  cart.sinpeRef = (document.getElementById('sinpe-reference').value || 'S/N').trim();

  // Unique Booking Code (cryptographically generated)
  const bookingCode = generateBookingCode();

  // Extras list text
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

🎵 *Formato:* ${cart.selectedService.name} (₡${cart.selectedService.price_crc.toLocaleString('es-CR')})
⏱️ *Duración:* ${cart.selectedService.duration}

➕ *EXTRAS COTIZADOS:*
${extrasFormatted}

📅 *Fecha & Hora:* ${cart.eventDate} @ ${cart.eventTime}
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

  // Populate Step 4 Voucher UI (textContent only, no user data in HTML)
  document.getElementById('confirm-booking-code').textContent = bookingCode;
  document.getElementById('confirm-client-name').textContent = cart.clientName;
  document.getElementById('confirm-event-type').textContent = cart.eventType;
  document.getElementById('confirm-service-name').textContent = cart.selectedService.name;
  document.getElementById('confirm-event-date').textContent = `${cart.eventDate} - ${cart.eventTime}`;
  document.getElementById('confirm-location').textContent = `${cart.canton}, ${cart.province}`;
  document.getElementById('confirm-gran-total').textContent = `₡${cart.granTotal.toLocaleString('es-CR')}`;
  document.getElementById('confirm-deposit-50').textContent = `₡${cart.deposit50Amount.toLocaleString('es-CR')}`;

  const waBtn = document.getElementById('btn-whatsapp-client');
  if (waBtn) {
    waBtn.href = whatsappUrl;
  }

  // Booking finalized: clear persisted draft so a refresh never duplicates it
  cart.clearStoredState();

  cart.isSubmitting = false;
  if (btn) {
    btn.disabled = false;
    btn.innerHTML = originalLabel;
  }

  goToStep(4);
  showToast('¡Voucher y enlace de WhatsApp generados!', 'success');
}

// Toast Notifications System
function showToast(message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast-item';

  if (type === 'error') {
    toast.classList.add('toast-error');
  }

  const icons = {
    success: '<svg class="w-5 h-5 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>',
    error: '<svg class="w-5 h-5 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>',
    info: '<svg class="w-5 h-5 text-purple-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
  };

  toast.innerHTML = `${icons[type] || icons.info} <span class="text-xs font-semibold">${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-out');
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

// Copy SINPE Number to Clipboard (footer click-to-copy)
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

// Copy Code to Clipboard (with fallback + error handling)
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
