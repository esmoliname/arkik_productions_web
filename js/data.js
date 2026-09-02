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
  maxEventsPerDay: 2, // Máximo 2 eventos por día — modelo diario puro
  defaultBookingStatus: "pendiente" // Inicia siempre como Pendiente de Aprobación
};

// EmailJS - Configuración del envío de comprobantes por correo.
// Deja los campos vacíos para operar en modo simulación (sin envío real).
// Consulta https://dashboard.emailjs.com para tus credenciales:
//   publicKey  -> Clave pública del proyecto (Account > General).
//   serviceID  -> ID del servicio SMTP registrado.
//   templateID -> ID de la plantilla del correo (Service ID > Templates).
const EMAILJS_CONFIG = {
  publicKey: "",
  serviceID: "",
  templateID: ""
};

// ============================================================
// PLANTILLA EMAILJS RECOMENDADA (Comprobante de Reserva)
// ============================================================
// Cuando se configuren las llaves reales en producción:
//   1. En https://dashboard.emailjs.com crea el Service (SMTP) y el Template.
//   2. Copia su Service ID y Template ID a EMAILJS_CONFIG y el Public Key.
//   3. La plantilla debe declarar estas variables (deben coincidir EXACTO
//      con las claves del payload que construye sendBookingEmail() en app.js):
//        client_name, client_email, booking_id, event_date, format_name,
//        total_amount, deposit_50, balance_50, sinpe_phone
//
// Asunto (Subject) sugerido:
//   Comprobante de Reserva Arkik Productions - {{booking_id}}
//
// Ejemplo de HTML del cuerpo de la plantilla:
//
//   <div style="font-family:Arial,sans-serif;background:#f4f4f7;padding:24px;">
//     <div style="max-width:620px;margin:auto;background:#fff;border-radius:12px;
//                  overflow:hidden;border:1px solid #e5e7eb;">
//       <div style="background:#6d28d9;color:#fff;padding:20px 24px;">
//         <h2 style="margin:0;font-size:20px;">ARKIK PRODUCTIONS</h2>
//         <p style="margin:4px 0 0;font-size:12px;opacity:.9;">
//           Música en Vivo & Sonido Profesional · Costa Rica</p>
//       </div>
//       <div style="padding:24px;">
//         <p>Hola <strong>{{client_name}}</strong>,</p>
//         <p>Gracias por reservar con Arkik Productions. Tu comprobante de reserva:</p>
//         <table style="width:100%;border-collapse:collapse;margin:18px 0;font-size:14px;">
//           <tr><td style="padding:6px 0;color:#6b7280;">Código de reserva:</td>
//               <td style="padding:6px 0;font-weight:bold;">{{booking_id}}</td></tr>
//           <tr><td style="padding:6px 0;color:#6b7280;">Formato / Servicio:</td>
//               <td style="padding:6px 0;font-weight:bold;">{{format_name}}</td></tr>
//           <tr><td style="padding:6px 0;color:#6b7280;">Fecha del evento:</td>
//               <td style="padding:6px 0;font-weight:bold;">{{event_date}}</td></tr>
//           <tr><td style="padding:6px 0;color:#6b7280;">Gran total:</td>
//               <td style="padding:6px 0;font-weight:bold;">{{total_amount}}</td></tr>
//           <tr><td style="padding:6px 0;color:#059669;">Adelanto SINPE (50%):</td>
//               <td style="padding:6px 0;color:#059669;font-weight:bold;">{{deposit_50}}</td></tr>
//           <tr><td style="padding:6px 0;color:#6b7280;">Saldo el día del evento:</td>
//               <td style="padding:6px 0;font-weight:bold;">{{balance_50}}</td></tr>
//         </table>
//         <p style="background:#f3e8ff;border:1px solid #d8b4fe;border-radius:8px;
//                   padding:12px;font-size:13px;color:#581c87;">
//           💳 Realiza el 50% vía SINPE Móvil al número <strong>{{sinpe_phone}}</strong>
//           a nombre de <strong>Juan José Ramírez Chaves</strong> y envía el comprobante
//           a nuestro WhatsApp oficial para confirmar tu reserva.</p>
//         <p style="font-size:12px;color:#9ca3af;margin-top:20px;">
//           Documento de validez comercial emitido por Arkik Productions · Granadilla, San José.</p>
//       </div>
//     </div>
//   </div>
//
// NOTA: usa la notación {{variable}} del editor de templates de EmailJS
// (Handlebars-like). Las variables del payload deben coincidir 1:1 con las
// claves del objeto que envía sendBookingEmail().

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
  { key: "instagram", label: "Instagram / Shows" },
  { key: "banda", label: "Banda en Vivo" },
  { key: "acustico", label: "Show Acústico" },
  { key: "tecnico", label: "Montajes Técnicos" }
];

// Category labels used on cards and filter counts
const GALLERY_CATEGORY_LABELS = {
  instagram: "Instagram / Show",
  banda: "Banda en Vivo",
  acustico: "Show Acústico",
  tecnico: "Montaje Técnico"
};

// Multimedia Library — Data-driven social cards & media showcases
// type: 'instagram' | 'video' | 'image'; category: 'instagram' | 'banda' | 'acustico' | 'tecnico'
const mediaLibrary = [
  {
    id: "ig-1",
    title: "Noches de Mareas",
    category: "instagram",
    type: "instagram",
    embedUrl: "",
    directUrl: "https://www.instagram.com/kikeramirezcr",
    url: "https://www.instagram.com/kikeramirezcr",
    thumbnail: "img/Foto Kike .jpg",
    caption: "Granadilla · San José — Show en Vivo & Saxofón Premium",
    subtitle: "Show en Vivo & Saxofón Premium",
    date: "Agosto 2026",
    featured: true
  },
  {
    id: "ig-2",
    title: "Live Sax & Beats Session",
    category: "instagram",
    type: "instagram",
    embedUrl: "",
    directUrl: "https://www.instagram.com/kikeramirezcr",
    url: "https://www.instagram.com/kikeramirezcr",
    thumbnail: "https://images.unsplash.com/photo-1520523839897-bd0b52f945a0?auto=format&fit=crop&w=800&q=80",
    caption: "Escazú · San José — Repertorio Pop, House & Jazz",
    subtitle: "Repertorio Pop, House & Jazz",
    date: "Agosto 2026",
    featured: false
  },
  {
    id: "band-1",
    title: "Show en Vivo Banda RT",
    category: "banda",
    type: "video",
    embedUrl: "https://www.youtube.com/embed/dQw4w9WgXcQ",
    directUrl: "https://www.instagram.com/kikeramirezcr",
    url: "https://www.instagram.com/kikeramirezcr",
    thumbnail: "https://images.unsplash.com/photo-1516450360452-9312f5e86fc7?auto=format&fit=crop&w=800&q=80",
    caption: "Festival de Verano · San José — Juan José & Banda Completa en Acción",
    subtitle: "Juan José & Banda Completa en Acción",
    date: "Julio 2026",
    featured: true
  },
  {
    id: "acust-1",
    title: "Sesión Acústica Íntima",
    category: "acustico",
    type: "image",
    embedUrl: "",
    directUrl: "https://www.instagram.com/kikeramirezcr",
    url: "https://www.instagram.com/kikeramirezcr",
    thumbnail: "https://images.unsplash.com/photo-1511671782779-c97d3d27a1d4?auto=format&fit=crop&w=800&q=80",
    caption: "Boda Exclusiva · Santa Ana — Voz, Guitarra & Saxofón Romántico",
    subtitle: "Voz, Guitarra & Saxofón Romántico",
    date: "Julio 2026",
    featured: false
  },
  {
    id: "tech-1",
    title: "Montaje de Audio 24-Bit",
    category: "tecnico",
    type: "image",
    embedUrl: "",
    directUrl: "https://www.instagram.com/kikeramirezcr",
    url: "https://www.instagram.com/kikeramirezcr",
    thumbnail: "https://images.unsplash.com/photo-1470225620780-dba8ba36b745?auto=format&fit=crop&w=800&q=80",
    caption: "Consolas Digitales & RCF Line Array — Equipos JBL / RCF & Consolas Behringer X32",
    subtitle: "Equipos JBL / RCF & Consolas Behringer X32",
    date: "Junio 2026",
    featured: false
  },
  {
    id: "ig-3",
    title: "Reel: Solo Sax en Atardecer",
    category: "instagram",
    type: "instagram",
    embedUrl: "",
    directUrl: "https://www.instagram.com/kikeramirezcr",
    url: "https://www.instagram.com/kikeramirezcr",
    thumbnail: "https://images.unsplash.com/photo-1525994886773-080587e161c2?auto=format&fit=crop&w=800&q=80",
    caption: "Papagayo · Guanacaste — Coctel VIP frente al mar con Saxofón Alto",
    subtitle: "Coctel VIP frente al mar",
    date: "Junio 2026",
    featured: true
  },
  {
    id: "band-2",
    title: "Banda RT — Gala Corporativa",
    category: "banda",
    type: "image",
    embedUrl: "",
    directUrl: "https://www.instagram.com/kikeramirezcr",
    url: "https://www.instagram.com/kikeramirezcr",
    thumbnail: "https://images.unsplash.com/photo-1501386761578-eac5c94b800a?auto=format&fit=crop&w=800&q=80",
    caption: "Centro de Convenciones · Heredia — Escenario principal y fiesta bailable",
    subtitle: "Escenario principal y fiesta bailable",
    date: "Mayo 2026",
    featured: false
  },
  {
    id: "tech-2",
    title: "Estructura Truss & Iluminación DMX",
    category: "tecnico",
    type: "image",
    embedUrl: "",
    directUrl: "https://www.instagram.com/kikeramirezcr",
    url: "https://www.instagram.com/kikeramirezcr",
    thumbnail: "https://images.unsplash.com/photo-1492684223066-81342ee5ff30?auto=format&fit=crop&w=800&q=80",
    caption: "Show Stage & Cabezas Móviles Pro — Montaje técnico para eventos de alto impacto",
    subtitle: "Montaje técnico para eventos de alto impacto",
    date: "Mayo 2026",
    featured: false
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
// Claves canónicas v3.3: availability = arkik_blocked_dates_v1, gallery = arkik_media_v1
// (los nombres de propiedad no cambian; las migraciones v3.2→v3.3 viven en js/app.js)
const STORAGE_KEYS = {
  cart: STORAGE_KEY,
  bookings: "arkik_bookings_v1",
  availability: "arkik_blocked_dates_v1",
  prices: "arkik_prices_v1",
  gallery: "arkik_media_v1",
  customConfig: "arkik_custom_config_v1",
  admin: ADMIN_CONFIG.storageKey,
  audit: "arkik_audit_v1"
};

// Capacidad diaria máxima de eventos
const DEFAULT_MAX_EVENTS_PER_DAY = LOGISTICS_CONFIG.maxEventsPerDay; // 2 eventos máx/día

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
