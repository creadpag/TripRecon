> 🛡️ **TripRecon** te lleva al siguiente nivel de reconocimiento ofensivo.  
> 🚀 Automatiza la recopilación de subdominios, registros DNS, fugas, Dorks, APIs y más con ⚡ estilo hacker y reportes HTML visuales.
> ![image](https://github.com/user-attachments/assets/1f080aaf-8735-43c8-b2a9-6da9e60f8798)

-----

# TripRecon: Herramienta de Reconocimiento y Análisis de Dominios

[](https://opensource.org/licenses/MIT)
[](https://www.python.org/downloads/)
[](https://www.google.com/search?q=https://github.com/creadpag/TripRecon)

> 🛡️ **TripRecon** te lleva al siguiente nivel de reconocimiento ofensivo.
> 🚀 Automatiza la recopilación de subdominios, registros DNS, fugas, Dorks, APIs y más con ⚡ estilo hacker y reportes HTML visuales.

-----

## ⚙️ Instalación

1.  **Clonar el repositorio:**

    ```bash
    git clone https://github.com/creadpag/TripRecon.git
    cd TripRecon
    ```

2.  **Instalar dependencias:**
    Crea un archivo `requirements.txt` en la raíz del proyecto con el siguiente contenido:

    ```
    requests
    dnspython
    rich
    Jinja2
    beautifulsoup4
    pandas
    openpyxl
    ```

    Luego, instala las librerías:

    ```bash
    pip install -r requirements.txt
    ```

    O puedes instalar las librerías manualmente:

    ```bash
    pip install requests dnspython rich Jinja2 beautifulsoup4 pandas openpyxl
    ```

**Requisitos:**

  * Python 3.8+
  * Librerías listadas arriba.

-----

## 🔑 Configuración de API Keys

Para obtener los resultados más completos y aprovechar todas las funcionalidades, es **altamente recomendable** configurar tus API Keys.

Abre el archivo `Recon.py` y busca la sección `api_keys` dentro de la función `main()`:

```python
api_keys = {
    "shodan": "TU_API_KEY_SHODAN",          # Reemplaza con tu clave de Shodan
    "securitytrails": "TU_API_KEY_SECURITYTRAILS", # Reemplaza con tu clave de SecurityTrails
    "google_api_key": "TU_API_KEY_GOOGLE", # Reemplaza con tu clave de Google Custom Search API
    "google_cse_id": "TU_ID_CSE_GOOGLE",   # Reemplaza con tu ID de Custom Search Engine
    "netlas": "TU_API_KEY_NETLAS",          # Reemplaza con tu clave de Netlas
    "hunterhow": "TU_API_KEY_HUNTERHOW"    # Reemplaza con tu clave de Hunter.how
}
```

Reemplaza los marcadores de posición con tus claves reales. Si dejas alguna clave en blanco (`""`), la funcionalidad correspondiente será omitida o intentará usar un método de scraping (si aplica, como en Google Dorks, el cual puede ser inestable y sujeto a bloqueos).

-----

## 🚀 Modos de Ejecución

`TripRecon` soporta dos modos de operación que son **mutuamente excluyentes**:

1.  **Análisis de un Dominio Único:** Utiliza la opción `-d` o `--domain`.
2.  **Análisis de una Lista de Dominios:** Utiliza la opción `-l` o `--list`.

**Debes elegir solo una de estas opciones al ejecutar el script.**

### 1\. Análisis de un Dominio Único

Para analizar un solo dominio, usa el argumento `-d` o `--domain` seguido del nombre del dominio.

**Sintaxis:**

```bash
python Recon.py -d <nombre_del_dominio>
```

**Ejemplo:**

```bash
python Recon.py -d example.com
```

Al finalizar el análisis, se creará una carpeta con el nombre del dominio (ej. `example_com`) en el directorio actual. Dentro de esta carpeta, encontrarás:

  * `recon_report_example.com.html`: Un informe HTML interactivo.
  * `recon_report_example.com.xlsx`: Un informe detallado en formato Excel.
  * `google_dork_downloads/`: Una subcarpeta que contendrá los archivos descargados encontrados por Google Dorks.

### 2\. Análisis de una Lista de Dominios

Para analizar múltiples dominios de una sola vez, crea un archivo de texto donde cada dominio esté en una nueva línea. Luego, usa el argumento `-l` o `--list` seguido de la ruta a ese archivo.

**Pasos:**

1.  **Crea tu archivo de dominios** (ej. `domains.txt`):

    ```
    domain1.com
    domain2.org
    sub.domain3.net
    ```

2.  **Ejecuta la herramienta:**

    **Sintaxis:**

    ```bash
    python Recon.py -l <ruta_al_archivo_de_dominios>
    ```

    **Ejemplo:**

    ```bash
    python Recon.py -l domains.txt
    ```

El script procesará cada dominio del archivo individualmente. Para cada dominio, se creará una carpeta separada (ej. `domain1_com`, `domain2_org`, etc.) que contendrá sus respectivos informes HTML, Excel y las descargas de Google Dorks.

-----

## 🧩 Funcionalidades Detalladas

  * **🌐 Resolución de IP:** Obtiene la dirección IP principal de un dominio.
  * **🔎 Subdominios:** Descubre subdominios potenciales utilizando bases de datos públicas como `crt.sh` y la API de `SecurityTrails` (requiere clave API).
  * **📡 Información desde Shodan:** Consulta la API de Shodan para obtener detalles sobre la organización, el país y los puertos abiertos asociados a la dirección IP del dominio (requiere clave API).
  * **📬 Registros DNS:** Recopila información crucial de los registros DNS del dominio (A, MX, NS).
  * **🔥 Google Dorks automáticos:** Ejecuta una serie predefinida de Google Dorks para descubrir archivos expuestos, configuraciones sensibles, paneles de administración y más. Soporta tanto la API de Google Custom Search (recomendado) como el web scraping.
  * **🩸 Fugas de información (ProxyNova):** Busca posibles menciones o fugas de datos relacionados con el dominio.
  * **📦 Descarga de archivos encontrados:** Si Google Dorks identifica enlaces a archivos (PDFs, DOCs, TXTs, etc.), `TripRecon` intentará descargarlos automáticamente.
  * **🧠 Netlas + Hunter.how integrados:** Consulta estas plataformas para obtener datos adicionales sobre la infraestructura de red, servicios y tecnologías asociadas al dominio (requieren claves API).
  * **📄 Reporte HTML con estilo terminal hacker:** Genera informes detallados y visualmente atractivos que consolidan toda la información recopilada.
  * **📊 Reporte Excel:** Además del HTML, se genera un reporte en formato Excel para un análisis de datos más estructurado.

-----

## 📁 Estructura de Salida del Proyecto

```
TripRecon/
├── Recon.py               # Script principal
├── requirements.txt       # Archivo de dependencias (para `pip install -r`)
├── domain_name_example_com/ # Carpeta de salida para el dominio 'example.com'
│   ├── recon_report_example.com.html
│   ├── recon_report_example.com.xlsx
│   └── google_dork_downloads/ # Archivos descargados por los dorks para este dominio
└── another_domain_org/    # Carpeta de salida para el dominio 'another.org'
    ├── recon_report_another.org.html
    ├── recon_report_another.org.xlsx
    └── google_dork_downloads/
# ... y así sucesivamente para cada dominio analizado
```

-----

## 👨‍💻 Autor

Creado con ❤️ por **CreadPag**
¡Forkea, contribuye, y no olvides dejar una ⭐ si te resultó útil\!

-----

## ⚠️ Disclaimer

> Esta herramienta es solo para fines **educativos** y de **pentesting autorizado**.
> El autor no se hace responsable por el uso indebido de esta herramienta o de cualquier información obtenida a través de ella.
> La información recopilada proviene de fuentes públicas y de APIs; la precisión y la actualidad de los datos dependen de dichas fuentes.

-----

🔥 **TripRecon** – Porque el reconocimiento es el primer paso hacia el control total. 🕶️

-----
