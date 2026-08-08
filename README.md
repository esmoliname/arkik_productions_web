# 🎸 Arkik Productions — Plataforma Web & Cotizador Inteligente 2026

Una Web App de alto rendimiento (Single Page Application - SPA) diseñada para la automatización de cotizaciones, gestión de viáticos y reservas vía **SINPE Móvil** y **WhatsApp** para la productora musical **Arkik Productions** (Granadilla, San José, Costa Rica).

![UI Preview](https://img.shields.io/badge/UI-Dark%20Purple%20Glassmorphism-a855f7?style=for-the-badge)
![Tech Stack](https://img.shields.io/badge/Stack-HTML5%20%7C%20TailwindCSS%20%7C%20VanillaJS-38bdf8?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Prototipo%20Elite%20v1.0-10b981?style=for-the-badge)

---

## ⚡ Características Principales

- **Catálogo Dinámico 2026:** Formatos musicales en vivo (Banda RT, Trío, Dúo, Solista y Alquiler de Sonido Pro).
- **Cotizador Matemático en Tiempo Real:**
  - Cálculo automático de horas extra (50% del costo base del paquete).
  - Multiplicadores para DJ en recesos y Subwoofers de 18".
- **Gestión Automática de Viáticos:** Recargo dinámico del 12% para eventos ubicados fuera del Gran Área Metropolitana (GAM).
- **Pasarela de Pago SINPE Móvil:** Regla de pago diferido (Cálculo del 50% de prima para apartado de fecha).
- **Notificación por WhatsApp:** Generación automática de resúmenes de reserva formateados e integrados directamente a la API de WhatsApp (`wa.me`).
- **Biblioteca Multimedia:** Sección dedicada a la exhibición de videos y fotografías en vivo del artista.

---

## 📁 Estructura del Proyecto

```text
arkik_static/
├── index.html        # Estructura principal (SPA) y Cotizador Modal
├── css/
│   └── styles.css    # Estilos Glassmorphism, animaciones y Notificaciones Toast
└── js/
    ├── data.js       # Base de datos de catálogo, tarifas y reglas de negocio
    └── app.js        # Engine reactivo (CartState), contadores y WhatsApp Builder
```

🚀 Despliegue Local
Para ejecutar el proyecto en entorno local:

Clonar el repositorio:

Bash
git clone <URL-DEL-REPOSITORIO>
Abrir index.html directamente en el navegador o ejecutar con Live Server en VS Code / Antigravity IDE.

© 2026 Arkik Productions — Granadilla, San José, Costa Rica.