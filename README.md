# 🛡️ TripRecon 2.0 – Reconocimiento Ofensivo Avanzado
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)  
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)  
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20MacOS-lightgrey)  
![Version](https://img.shields.io/badge/Version-2.0-red.svg)  
![Status](https://img.shields.io/badge/Status-Stable-success.svg)

> 🚀 Automatiza el reconocimiento ofensivo y la recopilación de información sobre dominios, subdominios, servicios y vulnerabilidades.  
> 🌐 Con soporte para **Google y Bing Dorks**, APIs de **Shodan, Netlas, SecurityTrails, Hunter.how**, y generación de **reportes visuales HTML y Excel**.  

![TripRecon 2.0 Banner](https://github.com/user-attachments/assets/1f080aaf-8735-43c8-b2a9-6da9e60f8798)

---

## ⚙️ Instalación

```bash
git clone https://github.com/creadpag/TripRecon.git
cd TripRecon
pip install -r requirements.txt
```

**Requisitos mínimos:**
- Python 3.8 o superior  
- Librerías: `requests`, `dnspython`, `rich`, `Jinja2`, `beautifulsoup4`, `pandas`, `openpyxl`

---

## 🔑 Configuración de API Keys

Edita `recon.py` y reemplaza tus claves dentro del diccionario:

```python
api_keys = {
    "shodan": "TU_API_KEY_SHODAN",
    "securitytrails": "TU_API_KEY_SECURITYTRAILS",
    "google_api_key": "TU_API_KEY_GOOGLE",
    "google_cse_id": "TU_ID_CSE_GOOGLE",
    "bing_api_key": "TU_API_KEY_BING",
    "netlas": "TU_API_KEY_NETLAS",
    "hunterhow": "TU_API_KEY_HUNTERHOW"
}
```

> ⚠️ Si alguna clave está vacía (`""`), TripRecon usará **métodos alternativos (scraping)** o ignorará esa integración.

---

## 🚀 Modos de Ejecución

### 🔹 Escanear un dominio
```bash
python recon.py -d example.com
```

### 🔹 Escanear una lista de dominios
```bash
python recon.py -l domains.txt
```

### 🔹 Añadir Dorks personalizados
```bash
python recon.py -d example.com --dork dorks.txt
```

---

## 🧩 Nuevas Funcionalidades 2.0

| Característica | Descripción |
|----------------|-------------|
| 🧠 **Dorks Personalizables** | Soporte para tus propios Google/Bing Dorks (`--dork archivo.txt`) |
| 🌍 **Búsqueda Multimotor** | API o scraping para Google (`--sinapigoogle`) y Bing (`--usebing`, `--sinapibing`) |
| 🔐 **Análisis de Headers** | Revisa cabeceras CSP, HSTS, XSS, Referrer-Policy (`--analyze-headers`) |
| ⚙️ **Detección de Tecnologías** | Identifica CMS, frameworks JS, servidores web, y sistemas analíticos (`--detect-tech`) |
| 🚪 **Escaneo Básico de Puertos** | Detecta puertos comunes abiertos (`--scan-ports`) |
| 🕵️‍♂️ **Integraciones Mejoradas** | APIs de Shodan, Netlas, SecurityTrails y Hunter.how |
| 💾 **Descarga de Archivos Dorkeados** | Guarda automáticamente archivos detectados (PDF, DOC, TXT...) |
| 📊 **Reportes Enriquecidos** | Reportes HTML con diseño “terminal hacker” + Excel estructurado por pestañas |
| ⚡ **CLI Mejorado** | Colores dinámicos y tablas con `rich` |

---

## 🧠 Ejemplos de Uso Avanzado

### Escaneo completo con todas las funciones
```bash
python recon.py -d example.com --scan-ports --analyze-headers --detect-tech
```

### Escaneo sin APIs (modo scraping)
```bash
python recon.py -d example.com --sinapigoogle --sinapibing
```

### Usando Bing en lugar de Google
```bash
python recon.py -d example.com --usebing
```

---

## 📁 Estructura de Resultados

```
TripRecon/
├── recon.py
├── requirements.txt
├── domains.txt
├── example_com/
│   ├── recon_report_example.com.html
│   ├── recon_report_example.com.xlsx
│   └── google_dork_downloads/
└── anotherdomain_org/
```

---

## 📊 Reportes

### 🖥️ **Reporte HTML**
Diseño tipo *terminal hacker*, con animaciones, bloques visuales y tablas interactivas.

### 📑 **Reporte Excel**
Estructura por hojas:
- General Info  
- DNS Records  
- Subdominios (SecurityTrails / crt.sh)  
- Shodan Info  
- Netlas Info  
- Hunter.how  
- Google & Bing Dorks  
- Security Headers  
- Technologies  
- Open Ports  
- Data Leaks  

---

## 🧰 Dependencias Clave

| Librería | Uso |
|-----------|-----|
| `requests` | Consultas HTTP y APIs |
| `dnspython` | Resolución DNS |
| `rich` | Interfaz CLI enriquecida |
| `Jinja2` | Generación de reportes HTML |
| `BeautifulSoup4` | Web scraping |
| `pandas` + `openpyxl` | Creación de reportes Excel |

---

## 🧬 Changelog v2.0

| Versión | Cambios |
|----------|----------|
| **2.0** | 🔥 Nueva interfaz CLI con `rich` |
| | 🧠 Detección de tecnologías (CMS, JS frameworks, servidores) |
| | 🧱 Análisis de headers de seguridad |
| | 🌍 Soporte para Bing Dorks (API / scraping) |
| | 🚪 Escaneo básico de puertos TCP comunes |
| | 💾 Descarga de archivos detectados por Dorks |
| | 📊 Reportes HTML/Excel rediseñados con más secciones |
| | 🧩 Modularidad y manejo de errores mejorado |
| **1.x** | Reconocimiento base: subdominios, Shodan, DNS, Google Dorks |

---

## 👨‍💻 Autor

Creado con ❤️ por **CreadPag**  
> ✨ Sígueme, contribuye, abre issues, y deja tu ⭐ si esta herramienta te ayuda en tu flujo de pentesting.

---

## ⚠️ Disclaimer

> Esta herramienta se distribuye con fines **educativos y de pentesting autorizado**.  
> El autor **no se hace responsable** del uso indebido ni de los resultados obtenidos.  
> Los datos provienen de fuentes públicas y APIs externas.

---

🔥 **TripRecon 2.0** — *Porque el reconocimiento es el primer paso hacia el control total.* 🕶️
