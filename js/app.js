// Arkik Productions - Elite State Management & Reactive UI Engine

class CartState {
  constructor() {
    this.selectedService = CATALOG_SERVICES[0];
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
  }

  // Calculate Extra Hours Cost (50% of selected service base price per hour)
  get extraHoursUnitPrice() {
    if (!this.selectedService) return 0;
    return Math.round(this.selectedService.price_crc * 0.50);
  }

  get extraHoursTotal() {
    return this.extraHoursUnitPrice * this.extraHoursCount;
  }

  // Calculate DJ Service Cost (₡75,000 per hour)
  get djTotal() {
    return DYNAMIC_EXTRAS_CONFIG.dj_service.unitPrice * this.djHoursCount;
  }

  // Calculate Subwoofers Cost (₡80,000 per unit)
  get subwoofersTotal() {
    return DYNAMIC_EXTRAS_CONFIG.subwoofers.unitPrice * this.subwoofersCount;
  }

  // Calculate Subtotal (Service + Extras)
  get subtotal() {
    const base = this.selectedService ? this.selectedService.price_crc : 0;
    return base + this.extraHoursTotal + this.djTotal + this.subwoofersTotal;
  }

  // Check if non-GAM travel surcharge applies (12%)
  get isNonGam() {
    if (!this.province) return false;
    return !GAM_PROVINCES.includes(this.province);
  }

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
}

// Global App Instance
const cart = new CartState();

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

function initApp() {
  renderCatalog(CATALOG_SERVICES);
  renderMediaGallery(MEDIA_GALLERY);
  setupEventListeners();
  populateProvinces();
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
          <img src="${service.image_url}" alt="${service.name}" class="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500" />
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

// Render Media Library (Biblioteca Multimedia)
function renderMediaGallery(items) {
  const container = document.getElementById('gallery-grid');
  if (!container) return;

  container.innerHTML = items.map((item, index) => {
    if (item.type === 'video') {
      return `
        <div class="glass-panel rounded-2xl overflow-hidden border border-purple-500/30 group">
          <div class="relative h-48 sm:h-56 bg-black">
            <iframe src="${item.embedUrl}" title="${item.title}" class="w-full h-full border-0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
          </div>
          <div class="p-4">
            <span class="text-[10px] font-bold text-pink-400 uppercase tracking-widest">${item.category} • Video en Vivo</span>
            <h4 class="text-sm font-bold text-white mt-1 group-hover:text-purple-300 transition-colors">${item.title}</h4>
            <p class="text-xs text-gray-400 mt-0.5">${item.subtitle}</p>
          </div>
        </div>
      `;
    } else {
      return `
        <div class="glass-panel rounded-2xl overflow-hidden border border-purple-500/30 group relative">
          <div class="relative h-48 sm:h-56 overflow-hidden">
            <img src="${item.imageUrl}" alt="${item.title}" class="w-full h-full object-cover group-hover:scale-110 transition-transform duration-500" />
            <div class="absolute inset-0 bg-gradient-to-t from-[#0b0914] via-transparent to-transparent"></div>
          </div>
          <div class="p-4">
            <span class="text-[10px] font-bold text-purple-400 uppercase tracking-widest">${item.category} • Fotografía</span>
            <h4 class="text-sm font-bold text-white mt-1 group-hover:text-purple-300 transition-colors">${item.title}</h4>
            <p class="text-xs text-gray-400 mt-0.5">${item.subtitle}</p>
          </div>
        </div>
      `;
    }
  }).join('');
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

  // Province change -> Populate Cantones & recalculate Non-GAM surcharge
  const provSelect = document.getElementById('booking-province');
  if (provSelect) {
    provSelect.addEventListener('change', (e) => {
      cart.province = e.target.value;
      populateCantones(e.target.value);
      updateSummaryPrices();
    });
  }

  // File Upload Preview
  const fileInput = document.getElementById('sinpe-proof-file');
  if (fileInput) {
    fileInput.addEventListener('change', handleFilePreview);
  }
}

// Modal Control
function openBookingModal(serviceId) {
  cart.selectedService = CATALOG_SERVICES.find(s => s.id === serviceId) || CATALOG_SERVICES[0];
  cart.extraHoursCount = 0;
  cart.djHoursCount = 0;
  cart.subwoofersCount = 0;
  cart.province = "";
  cart.canton = "";
  
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
}

// Step Navigation
function goToStep(stepNumber) {
  if (stepNumber === 3 && cart.currentStep === 2) {
    const form = document.getElementById('booking-form-step2');
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }

    // Save Step 2 Form Values
    cart.clientName = document.getElementById('client-name').value;
    cart.clientPhone = document.getElementById('client-phone').value;
    cart.clientEmail = document.getElementById('client-email').value;
    cart.eventType = document.getElementById('event-type').value;
    cart.eventDate = document.getElementById('booking-date').value;
    cart.eventTime = document.getElementById('booking-time').value;
    cart.canton = document.getElementById('booking-canton').value;
    cart.address = document.getElementById('booking-address').value;
  }

  cart.currentStep = stepNumber;
  updateModalStep(stepNumber);
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

// Render Counters for Extras (Hora Extra 50%, DJ ₡75k, Subwoofers ₡80k)
function renderDynamicExtrasCounters() {
  const container = document.getElementById('extras-container');
  if (!container) return;

  const extraHourPrice = cart.extraHoursUnitPrice;

  container.innerHTML = `
    <!-- Extra Hours Counter -->
    <div class="p-4 rounded-xl glass-panel border border-purple-500/30 flex items-center justify-between">
      <div>
        <div class="flex items-center space-x-2">
          <span class="text-sm font-bold text-white">Hora(s) Adicional(es) de Show</span>
          <span class="text-[10px] font-extrabold px-2 py-0.5 rounded bg-purple-900/60 text-purple-300 border border-purple-500/40">50% del Base</span>
        </div>
        <p class="text-xs text-gray-400 mt-0.5">₡${extraHourPrice.toLocaleString('es-CR')} por hora adicional (50% de ₡${cart.selectedService.price_crc.toLocaleString('es-CR')})</p>
      </div>

      <div class="flex items-center space-x-3">
        <button type="button" onclick="adjustExtra('extraHoursCount', -1)" class="w-8 h-8 rounded-lg bg-purple-900/40 border border-purple-500/30 text-purple-300 font-bold hover:bg-purple-800/60 flex items-center justify-center text-lg">-</button>
        <span class="text-base font-extrabold text-white w-6 text-center">${cart.extraHoursCount}</span>
        <button type="button" onclick="adjustExtra('extraHoursCount', 1)" class="w-8 h-8 rounded-lg bg-purple-900/40 border border-purple-500/30 text-purple-300 font-bold hover:bg-purple-800/60 flex items-center justify-center text-lg">+</button>
      </div>
    </div>

    <!-- DJ Service Counter -->
    <div class="p-4 rounded-xl glass-panel border border-purple-500/30 flex items-center justify-between">
      <div>
        <div class="flex items-center space-x-2">
          <span class="text-sm font-bold text-white">Servicio de DJ para Recesos</span>
          <span class="text-xs font-bold text-pink-400">₡75,000 / hr</span>
        </div>
        <p class="text-xs text-gray-400 mt-0.5">Música continua y mezcla en vivo durante descansos</p>
      </div>

      <div class="flex items-center space-x-3">
        <button type="button" onclick="adjustExtra('djHoursCount', -1)" class="w-8 h-8 rounded-lg bg-purple-900/40 border border-purple-500/30 text-purple-300 font-bold hover:bg-purple-800/60 flex items-center justify-center text-lg">-</button>
        <span class="text-base font-extrabold text-white w-6 text-center">${cart.djHoursCount}</span>
        <button type="button" onclick="adjustExtra('djHoursCount', 1)" class="w-8 h-8 rounded-lg bg-purple-900/40 border border-purple-500/30 text-purple-300 font-bold hover:bg-purple-800/60 flex items-center justify-center text-lg">+</button>
      </div>
    </div>

    <!-- Subwoofers Counter -->
    <div class="p-4 rounded-xl glass-panel border border-purple-500/30 flex items-center justify-between">
      <div>
        <div class="flex items-center space-x-2">
          <span class="text-sm font-bold text-white">Subwoofers Extra de 18"</span>
          <span class="text-xs font-bold text-pink-400">₡80,000 / un</span>
        </div>
        <p class="text-xs text-gray-400 mt-0.5">Potencia adicional de bajos para salones grandes o al aire libre</p>
      </div>

      <div class="flex items-center space-x-3">
        <button type="button" onclick="adjustExtra('subwoofersCount', -1)" class="w-8 h-8 rounded-lg bg-purple-900/40 border border-purple-500/30 text-purple-300 font-bold hover:bg-purple-800/60 flex items-center justify-center text-lg">-</button>
        <span class="text-base font-extrabold text-white w-6 text-center">${cart.subwoofersCount}</span>
        <button type="button" onclick="adjustExtra('subwoofersCount', 1)" class="w-8 h-8 rounded-lg bg-purple-900/40 border border-purple-500/30 text-purple-300 font-bold hover:bg-purple-800/60 flex items-center justify-center text-lg">+</button>
      </div>
    </div>
  `;
}

function adjustExtra(key, delta) {
  const current = cart[key] || 0;
  const newValue = Math.max(0, current + delta);
  cart[key] = newValue;
  
  renderDynamicExtrasCounters();
  updateSummaryPrices();

  if (delta > 0) {
    showToast("Cotización actualizada (+)");
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

  const surchargeBox = document.getElementById('surcharge-notice-box');
  if (surchargeBox) {
    if (cart.isNonGam) {
      surchargeBox.innerHTML = `
        <div class="p-3 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-300 text-xs flex justify-between items-center">
          <span> Recargo del 12% por viáticos fuera del GAM (${cart.province}):</span>
          <span class="font-bold text-amber-200">+₡${cart.travelSurcharge.toLocaleString('es-CR')}</span>
        </div>
      `;
    } else {
      surchargeBox.innerHTML = `
        <div class="p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs flex justify-between items-center">
          <span>✓ Cobertura dentro del GAM (${cart.province || 'San José'}):</span>
          <span class="font-bold text-emerald-200">₡0 (Gratis)</span>
        </div>
      `;
    }
  }
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
  
  const list = PROVINCES_AND_CANTONES[province] || ["Central", "Montes de Oca"];
  cantonSelect.innerHTML = '<option value="">Seleccione Cantón...</option>' + 
    list.map(c => `<option value="${c}">${c}</option>`).join('');
}

// File Upload Preview
function handleFilePreview(e) {
  const file = e.target.files[0];
  const previewBox = document.getElementById('file-preview-box');
  const previewName = document.getElementById('file-preview-name');

  if (file && previewBox && previewName) {
    previewName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    previewBox.classList.remove('hidden');
    showToast("Comprobante adjuntado listo");
  }
}

// Finalize Static Booking & Generate WhatsApp URL Breakdown
function submitStaticBooking() {
  cart.sinpeRef = document.getElementById('sinpe-reference').value || 'S/N';

  // Generate Unique Booking Code
  const randomHex = Math.floor(Math.random() * 16777215).toString(16).toUpperCase().padStart(6, '0');
  const bookingCode = `ARK-${randomHex}`;

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

🎵 *Formato:* ${cart.selectedService.name} (₡${cart.selectedService.price_crc.toLocaleString('es-CR')})
⏱️ *Duración Estándar:* 2 Horas

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
*Adjunto foto del comprobante SINPE del 50% en este chat.*`;

  const encodedMsg = encodeURIComponent(rawMsg);
  const whatsappUrl = `https://wa.me/${SINPE_CONFIG.cleanPhone}?text=${encodedMsg}`;

  // Populate Step 4 Voucher UI
  document.getElementById('confirm-booking-code').textContent = bookingCode;
  document.getElementById('confirm-client-name').textContent = cart.clientName;
  document.getElementById('confirm-service-name').textContent = cart.selectedService.name;
  document.getElementById('confirm-event-date').textContent = `${cart.eventDate} - ${cart.eventTime}`;
  document.getElementById('confirm-location').textContent = `${cart.canton}, ${cart.province}`;
  document.getElementById('confirm-gran-total').textContent = `₡${cart.granTotal.toLocaleString('es-CR')}`;
  document.getElementById('confirm-deposit-50').textContent = `₡${cart.deposit50Amount.toLocaleString('es-CR')}`;

  const waBtn = document.getElementById('btn-whatsapp-client');
  if (waBtn) {
    waBtn.href = whatsappUrl;
  }

  goToStep(4);
  showToast("¡Voucher y enlace de WhatsApp generados!", "success");
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
  toast.className = `toast-item`;
  
  const icon = type === 'success' 
    ? '<svg class="w-5 h-5 text-emerald-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>'
    : '<svg class="w-5 h-5 text-purple-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';

  toast.innerHTML = `${icon} <span class="text-xs font-semibold">${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-out');
    setTimeout(() => toast.remove(), 300);
  }, 2500);
}

// Copy Code to Clipboard
function copyBookingCode() {
  const codeEl = document.getElementById('confirm-booking-code');
  if (codeEl) {
    navigator.clipboard.writeText(codeEl.textContent);
    showToast(`Código ${codeEl.textContent} copiado al portapapeles.`, 'success');
  }
}
