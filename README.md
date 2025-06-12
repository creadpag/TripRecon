> 🛡️ **TripRecon** te lleva al siguiente nivel de reconocimiento ofensivo.  
> 🚀 Automatiza la recopilación de subdominios, registros DNS, fugas, Dorks, APIs y más con ⚡ estilo hacker y reportes HTML visuales.

---

## ⚙️ Instalación

```bash
git clone https://github.com/creadpag/TripRecon.git
cd triprecon
pip install -r requirements.txt
````

**Requisitos:**

* Python 3.8+
* Librerías: `requests`, `dnspython`, `rich`, `jinja2`, `urllib3`

O puedes instalar manualmente:

```bash
pip install requests dnspython rich jinja2 urllib3
```

---

## 🚀 Ejecución Rápida

```bash
python Recon.py -d example.com
```

📁 El reporte se guarda como `recon_report_example.com.html`.

---

## 🔑 APIs Soportadas

Edita las API keys en `Recon.py`:

```python
api_keys = {
    "shodan": "TU_API_KEY",
    "securitytrails": "TU_API_KEY",
    "google_api_key": "TU_API_KEY",
    "google_cse_id": "TU_CSE_ID",
    "netlas": "TU_API_KEY",
    "hunterhow": "TU_API_KEY"
}
```

---

## 🧩 Funcionalidades

* 🌐 Resolución de IP
* 🔎 Subdominios (`crt.sh` y `SecurityTrails`)
* 📡 Información desde Shodan
* 📬 Registros DNS (A, MX, NS)
* 🔥 Google Dorks automáticos
* 🩸 Fugas de información (ProxyNova)
* 📦 Descarga de archivos encontrados
* 🧠 Netlas + Hunter.how integrados
* 📄 Reporte HTML con estilo terminal hacker

---

## 📁 Estructura del Proyecto

```
triprecon/
├── Recon.py              # Script principal
├── requirements.txt      # Dependencias
├── downloads/            # Archivos descargados por los dorks
└── recon_report_*.html   # Reportes generados
```

---

## 👨‍💻 Autor

Creado con ❤️ por **CreadPag**
¡Forkea, contribuye, y no olvides dejar una ⭐ si te resultó útil!

---

## ⚠️ Disclaimer

> Esta herramienta es solo para fines **educativos** y de **pentesting autorizado**.
> El autor no se hace responsable por el uso indebido.

---

🔥 **TripRecon** – Porque el reconocimiento es el primer paso hacia el control total. 🕶️
