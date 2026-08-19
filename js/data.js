// Arkik Productions - Real Business Data & Configuration (2026)

const SINPE_CONFIG = {
  phone: "+506 6227-4984",
  cleanPhone: "50662274984",
  holder: "Juan José Ramírez Chaves",
  depositPercentage: 0.50,
  locationHQ: "Granadilla, San José",
  policyText: "El adelanto del 50% vía SINPE Móvil no es reembolsable. Se coordinará reprogramación de fecha sujeta a disponibilidad de agenda (excepto por negligencia o falta de comunicación)."
};

const LOGISTICS_CONFIG = {
  minNoticeHours: 72, // 3 días de antelación mínima obligatoria
  maxHorizonDays: 365, // Horizonte máximo de 1 año calendario
  maxEventsPerDay: 2, // Máximo 2 eventos por día
  minIntervalHours: 5, // Margen mínimo de traslado / descanso entre eventos (5 a 6 horas)
  recommendedIntervalHours: 6,
  defaultBookingStatus: "pendiente" // Inicia siempre como Pendiente de Aprobación
};

const GAM_PROVINCES = ["San José", "Heredia", "Alajuela", "Cartago"];
const NON_GAM_SURCHARGE_RATE = 0.12; // 12% surcharge for provinces outside GAM

// Cantons located inside GAM provinces that are geographically OUTSIDE the GAM.
// These must be charged the 12% travel surcharge even though their province is in GAM.
const NON_GAM_EXCEPTIONS = {
  "San José": ["Pérez Zeledón"],
  "Heredia": ["Sarapiquí"],
  "Cartago": ["Turrialba"]
};

// Hard caps for the extras counters (max selectable units per line item).
// Keys must match CartState property names.
const MAX_EXTRAS = {
  extraHoursCount: 6,
  djHoursCount: 6,
  subwoofersCount: 4
};

// localStorage key used to recover an in-flight quote after a page refresh.
const STORAGE_KEY = "arkik_cart_state_v1";

const CATALOG_SERVICES = [
  {
    id: 1,
    name: "Banda Completa (Banda RT)",
    category: "Música en Vivo",
    description: "Formato completo con 5 músicos en escena, instrumentos profesionales y sistema de sonido integrado. La mejor opción para bodas estelares, eventos corporativos y fiestas.",
    price_crc: 650000,
    duration: "2 Horas (Duración Estándar)",
    setup_time_mins: 150, // 2.5 horas antes
    teardown_time_mins: 90, // 1.5 horas después
    setup_display: "2.5 horas antes",
    teardown_display: "1.5 horas después",
    tech_specs: "5 Músicos en escena, instrumentos profesionales, monitoreo In-Ear y sistema PA completo.",
    image_url: "https://images.unsplash.com/photo-1516450360452-9312f5e86fc7?auto=format&fit=crop&w=800&q=80",
    badge: "Formato Estelar",
    is_popular: true
  },
  {
    id: 2,
    name: "Cuarteto Arkik",
    category: "Música en Vivo",
    description: "4 músicos en escena con percusión/batería híbrida, bajo, armonía, voz y sonido profesional. Potencia y elegancia versátil para recepciones y fiestas.",
    price_crc: 480000,
    duration: "2 Horas (Duración Estándar)",
    setup_time_mins: 120, // 2 horas antes
    teardown_time_mins: 60, // 1 hora después
    setup_display: "2 horas antes",
    teardown_display: "1 hora después",
    tech_specs: "4 Músicos en escena, percusión, bajo, guitarra/teclado, voz principal y PA estéreo.",
    image_url: "https://images.unsplash.com/photo-1501386761578-eac5c94b800a?auto=format&fit=crop&w=800&q=80",
    badge: "Versatilidad Total",
    is_popular: false
  },
  {
    id: 3,
    name: "Trío Acústico Premium",
    category: "Música en Vivo",
    description: "3 músicos en vivo con instrumentos y sonido profesional. Aporta una vibra elegante, fresca y enérgica para recepciones y cocteles.",
    price_crc: 380000,
    duration: "2 Horas (Duración Estándar)",
    setup_time_mins: 105, // 1 hora 45 min antes
    teardown_time_mins: 45, // 45 min después
    setup_display: "1h 45m antes",
    teardown_display: "45 min después",
    tech_specs: "3 Músicos en vivo, instrumentos acústicos/eléctricos y microfonía profesional.",
    image_url: "https://images.unsplash.com/photo-1511671782779-c97d3d27a1d4?auto=format&fit=crop&w=800&q=80",
    badge: "Elegancia Pura",
    is_popular: false
  },
  {
    id: 4,
    name: "Dúo Íntimo Arkik",
    category: "Música en Vivo",
    description: "2 músicos en vivo con 1 instrumento acompañante y sonido. Formato ideal para ceremonias de boda, cenas de gala y espacios acogedores.",
    price_crc: 250000,
    duration: "2 Horas (Duración Estándar)",
    setup_time_mins: 90, // 1.5 horas antes
    teardown_time_mins: 60, // 1 hora después
    setup_display: "1.5 horas antes",
    teardown_display: "1 hora después",
    tech_specs: "2 Músicos en vivo, 1 instrumento armónico y sistema de audio estéreo.",
    image_url: "https://images.unsplash.com/photo-1465847899084-d164df4dedc6?auto=format&fit=crop&w=800&q=80",
    badge: "Recomendado Ceremonia",
    is_popular: false
  },
  {
    id: 5,
    name: "Solista Instrumental / Cantante",
    category: "Música en Vivo",
    description: "Voz en vivo, saxofón/guitarra, secuencias de acompañamiento de alta fidelidad y sistema de sonido. Presentación solista emotiva y refinada.",
    price_crc: 150000,
    duration: "2 Horas (Duración Estándar)",
    setup_time_mins: 60, // 1 hora antes
    teardown_time_mins: 30, // 30 min después
    setup_display: "1 hora antes",
    teardown_display: "30 min después",
    tech_specs: "Voz / Instrumento solista, pistas backing tracks HD y audio personal.",
    image_url: "https://images.unsplash.com/photo-1520523839897-bd0b52f945a0?auto=format&fit=crop&w=800&q=80",
    badge: "Ideal Coctel",
    is_popular: false
  },
  {
    id: 6,
    name: "Alquiler Sonido e Iluminación Pro",
    category: "Alquiler de Sonido",
    description: "Parlantes activos de alta potencia, luces ambientales LED, microfonía inalámbrica, mezcladores digitales, estructuras truss y soporte técnico.",
    price_crc: 250000,
    duration: "Jornada de Evento",
    setup_time_mins: 120, // 2 horas antes
    teardown_time_mins: 90, // 1.5 horas después
    setup_display: "2 horas antes",
    teardown_display: "1.5 horas después",
    tech_specs: "Parlantes activos, luces LED, consolas digitales, microfonía y operador de audio.",
    image_url: "https://images.unsplash.com/photo-1470225620780-dba8ba36b745?auto=format&fit=crop&w=800&q=80",
    badge: "Producción Técnica",
    is_popular: false
  }
];

const DYNAMIC_EXTRAS_CONFIG = {
  extra_hours: {
    id: "extra_hours",
    name: "Hora(s) Adicional(es) de Show",
    calcType: "50_percent_base",
    desc: "Cada hora adicional equivale al 50% de la tarifa base del paquete seleccionado."
  },
  dj_service: {
    id: "dj_service",
    name: "Servicio de DJ para Recesos",
    unitPrice: 75000,
    desc: "₡75,000 por hora de mezcla continua durante los descansos de la presentación."
  },
  subwoofers: {
    id: "subwoofers",
    name: "Subwoofers Extra de 18\"",
    unitPrice: 80000,
    desc: "₡80,000 por unidad para reforzar eventos al aire libre o salones amplios."
  }
};

// Gallery filter definitions (rendered dynamically in #gallery-filters)
const GALLERY_FILTERS = [
  { key: "todos", label: "Todos" },
  { key: "banda", label: "Banda en Vivo" },
  { key: "acustico", label: "Show Acústico" },
  { key: "tecnico", label: "Montaje Técnico" }
];

// Category labels used on cards and filter counts
const GALLERY_CATEGORY_LABELS = {
  banda: "Banda en Vivo",
  acustico: "Show Acústico",
  tecnico: "Montaje Técnico"
};

// Multimedia Library — add/remove gallery items here only.
// type: 'video' (YouTube embed URL) | 'image'; category: banda | acustico | tecnico
const mediaLibrary = [
  {
    id: 1,
    type: "video",
    title: "Banda RT en Vivo — Highlights Festival",
    subtitle: "Juan José & Banda Completa en Acción",
    category: "banda",
    url: "https://www.youtube.com/embed/5qap5aO4i9A",
    thumbnail: "https://images.unsplash.com/photo-1516450360452-9312f5e86fc7?auto=format&fit=crop&w=800&q=80"
  },
  {
    id: 2,
    type: "image",
    title: "Trío Acústico Premium — Recepción de Boda",
    subtitle: "Granadilla / Escazú, Costa Rica",
    category: "acustico",
    url: "https://images.unsplash.com/photo-1511671782779-c97d3d27a1d4?auto=format&fit=crop&w=800&q=80",
    thumbnail: "https://images.unsplash.com/photo-1511671782779-c97d3d27a1d4?auto=format&fit=crop&w=800&q=80"
  },
  {
    id: 3,
    type: "image",
    title: "Dúo Íntimo Arkik — Ceremonia Romántica",
    subtitle: "Voz & Teclado Electroacústico",
    category: "acustico",
    url: "https://images.unsplash.com/photo-1465847899084-d164df4dedc6?auto=format&fit=crop&w=800&q=80",
    thumbnail: "https://images.unsplash.com/photo-1465847899084-d164df4dedc6?auto=format&fit=crop&w=800&q=80"
  },
  {
    id: 4,
    type: "video",
    title: "Juan José Ramírez — Performance Solista",
    subtitle: "Show de Saxofón & Pistas HD",
    category: "acustico",
    url: "https://www.youtube.com/embed/dQw4w9WgXcQ",
    thumbnail: "https://images.unsplash.com/photo-1520523839897-bd0b52f945a0?auto=format&fit=crop&w=800&q=80"
  },
  {
    id: 5,
    type: "image",
    title: "Montaje Técnico de Sonido e Iluminación Pro",
    subtitle: "Equipos JBL / RCF & Consolas Behringer X32",
    category: "tecnico",
    url: "https://images.unsplash.com/photo-1470225620780-dba8ba36b745?auto=format&fit=crop&w=800&q=80",
    thumbnail: "https://images.unsplash.com/photo-1470225620780-dba8ba36b745?auto=format&fit=crop&w=800&q=80"
  },
  {
    id: 6,
    type: "image",
    title: "Banda RT en Evento Corporativo VIP",
    subtitle: "San José, Costa Rica",
    category: "banda",
    url: "https://images.unsplash.com/photo-1501386761578-eac5c94b800a?auto=format&fit=crop&w=800&q=80",
    thumbnail: "https://images.unsplash.com/photo-1501386761578-eac5c94b800a?auto=format&fit=crop&w=800&q=80"
  }
];

const PROVINCES_AND_CANTONES = {
  "San José": ["Montes de Oca", "Escazú", "Santa Ana", "Central (San José)", "Curridabat", "Pérez Zeledón", "Desamparados", "Moravia", "Tibás", "Goicoechea", "Aserrí", "Mora", "Vázquez de Coronado"],
  "Alajuela": ["Central (Alajuela)", "San Carlos", "Grecia", "Atenas", "San Ramón", "Palmares", "Poás", "Orotina"],
  "Cartago": ["Central (Cartago)", "La Unión (Tres Ríos)", "Paraíso", "El Guarco", "Oreamuno", "Alvarado", "Turrialba"],
  "Heredia": ["Central (Heredia)", "Belén", "Barva", "Santo Domingo", "San Rafael", "San Isidro", "Flores", "Sarapiquí"],
  "Guanacaste": ["Liberia", "Santa Cruz", "Nicoya", "Carrillo (Playas del Coco)", "Cañas", "Tilarán", "Abangares", "La Cruz"],
  "Puntarenas": ["Central (Puntarenas)", "Garabito (Jacó)", "Quepos (Manuel Antonio)", "Esparza", "Osa (Uvita/Dominical)", "Golfito"],
  "Limón": ["Central (Limón)", "Pococí (Guápiles)", "Talamanca (Puerto Viejo/Cahuita)", "Siquirres", "Matina"]
};

// ---- Security & Administration Configuration (v3) ----
// PIN por defecto (hash verificado en runtime con SHA-256):
//   Propietario  -> 2580   |   Ingeniero de TI -> 1234

const ADMIN_CONFIG = {
  roles: {
    owner: {
      id: "owner",
      label: "Propietario",
      name: "Juan José Ramírez",
      hashKey: "ownerHash",
      defaultPin: "2580"
    },
    it: {
      id: "it",
      label: "Ingeniero de TI",
      name: "Esteban Molina",
      hashKey: "itHash",
      defaultPin: "1234"
    }
  },
  maxAttempts: 3,
  lockoutMs: 30000,
  sessionTimeoutMs: 300000,
  storageKey: "arkik_admin_auth_v1"
};

// Versión del motor de operaciones (auditoría del sistema en el rol IT)
const ENGINE_VERSION = "arkik-engine-v3.2.0";

// Claves de persistencia local (por dominio, con fallback seguro)
const STORAGE_KEYS = {
  cart: STORAGE_KEY,
  bookings: "arkik_bookings_v1",
  availability: "arkik_availability_v1",
  prices: "arkik_prices_v1",
  admin: ADMIN_CONFIG.storageKey,
  audit: "arkik_audit_v1"
};

// Capacidad diaria máxima de eventos
const DEFAULT_MAX_EVENTS_PER_DAY = LOGISTICS_CONFIG.maxEventsPerDay; // 2 eventos máx/día

// Franjas horarias del selector de turnos (Mañana / Tarde / Noche)
const TIME_SLOTS = {
  morning: {
    id: "morning",
    label: "Turno Mañana",
    range: "08:00 - 12:00",
    times: ["08:00", "09:00", "10:00", "11:00", "12:00"],
    icon: "☀️"
  },
  afternoon: {
    id: "afternoon",
    label: "Turno Tarde",
    range: "13:00 - 17:00",
    times: ["13:00", "14:00", "15:00", "16:00", "17:00"],
    icon: "🌤️"
  },
  night: {
    id: "night",
    label: "Turno Noche",
    range: "18:00 - 02:00",
    times: ["18:00", "19:00", "20:00", "21:00", "22:00", "23:00", "00:00", "01:00", "02:00"],
    icon: "🌙"
  }
};

const CALENDAR_LOCALE = {
  months: ["Enero", "Febrero", "Marzo", "Abril", "Mayo", "Junio", "Julio", "Agosto", "Septiembre", "Octubre", "Noviembre", "Diciembre"],
  weekdays: ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"]
};

const BOOKING_STATUSES = {
  pendiente: "Pendiente de Aprobación",
  confirmada: "Confirmada",
  realizada: "Realizada",
  cancelada: "Cancelada"
};
