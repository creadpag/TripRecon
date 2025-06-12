import os
import requests
import json
import argparse
import socket
import dns.resolver
import urllib3
import subprocess
import base64
from datetime import datetime
from jinja2 import Template
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# Deshabilitar advertencias de solicitudes inseguras
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Crear una instancia de Console para rich
console = Console()

# Banner estilo hacker con rich para TripRecon
def print_hacker_banner():
    banner = r"""
___________      .__      __________                            
\__    ___/______|__|_____\______   \ ____   ____  ____   ____  
  |    |  \_  __ \  \____ \|       _// __ \_/ ___\/  _ \ /    \ 
  |    |   |  | \/  |  |_> >    |   \  ___/\  \__(  <_> )   |  \
  |____|   |__|  |__|   __/|____|_  /\___  >\___  >____/|___|  /
                    |__|          \/     \/     \/           \/ 

    """
    console.print(Panel.fit(Text(banner, style="bold green"), 
              title="[blink]TripRecon[/blink]", 
              subtitle="[blue]by CreadPag[/]",
              border_style="blue"))

# Función para manejar los argumentos de la línea de comandos
def parse_args():
    parser = argparse.ArgumentParser(description="Reconocimiento y análisis de dominios con herramientas hacker.")
    parser.add_argument("-d", "--domain", type=str, required=True, help="Dominio a analizar")
    return parser.parse_args()

# Función para obtener la IP de un dominio
def get_ip_from_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"[bold green]IP de {domain}:[/bold green] {ip}")
        return ip
    except socket.gaierror as e:
        console.print(f"[bold red]Error al obtener IP de {domain}:[/bold red] {e}")
        return f"Error al obtener IP de {domain}: {e}"

# Función para limpiar texto de caracteres no deseados
def clean_text(text):
    if isinstance(text, str):
        return text.replace('{', '').replace('}', '').replace("'", "").replace('"', '').replace('[', '').replace(']', '').replace('@', '')
    elif isinstance(text, list):
        return [clean_text(item) for item in text]
    elif isinstance(text, dict):
        # No limpiar diccionarios que contengan datos estructurados
        if any(key in text for key in ['data', 'items', 'list']):
            return {k: clean_text(v) for k, v in text.items()}
        return {clean_text(k): clean_text(v) for k, v in text.items()}
    return text

# Función para obtener subdominios de crt.sh
def get_crtsh_subdomains(domain):
    BASE_URL = "https://crt.sh/?q={}&output=json"
    subdomains = set()
    wildcardsubdomains = set()

    try:
        response = requests.get(BASE_URL.format(domain), timeout=25)
        if response.ok:
            content = response.content.decode('UTF-8')
            jsondata = json.loads(content)
            for entry in jsondata:
                name_value = clean_text(entry['name_value'])
                if '\n' in name_value:
                    subname_values = name_value.split('\n')
                    for subname_value in subname_values:
                        if '*' in subname_value:
                            wildcardsubdomains.add(subname_value)
                        else:
                            subdomains.add(subname_value)
                else:
                    if '*' in name_value:
                        wildcardsubdomains.add(name_value)
                    else:
                        subdomains.add(name_value)
    except Exception as e:
        console.print(f"[bold red]Error al obtener subdominios de crt.sh:[/bold red] {e}")
        return None

    # Obtener IPs para los subdominios
    subdomains_with_ips = []
    for subdomain in subdomains:
        try:
            ip = socket.gethostbyname(subdomain)
            subdomains_with_ips.append({"subdomain": subdomain, "ip": ip})
        except socket.gaierror:
            subdomains_with_ips.append({"subdomain": subdomain, "ip": "No encontrada"})

    # Mostrar los subdominios en una tabla con rich
    table = Table(title="Subdominios de crt.sh", show_header=True, header_style="bold green")
    table.add_column("Subdominio")
    table.add_column("IP")
    for item in subdomains_with_ips:
        table.add_row(item["subdomain"], item["ip"])
    console.print(table)

    # Mostrar los subdominios con wildcard si se solicita
    if wildcardsubdomains:
        table = Table(title="Subdominios Wildcard de crt.sh", show_header=True, header_style="bold yellow")
        table.add_column("Subdominio Wildcard")
        for wildcard in wildcardsubdomains:
            table.add_row(wildcard)
        console.print(table)

    return subdomains_with_ips, list(wildcardsubdomains)

# Función para obtener información de Shodan
def get_shodan_info(api_key, ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        response = requests.get(url)
        data = response.json()
        if 'error' in data:
            console.print(f"[bold red]Error en Shodan:[/bold red] {data['error']}")
            return {"error": data['error']}
        
        shodan_info = {
            'ip': ip,
            'ports': sorted(data.get('ports', [])),
            'org': data.get('org', 'Desconocido'),
            'country': data.get('country_name', 'Desconocido'),
            'hostnames': data.get('hostnames', [])
        }
        
        # Mostrar la información de Shodan en una tabla con rich
        table = Table(title="Información de Shodan", show_header=True, header_style="bold magenta")
        table.add_column("Campo", style="dim", width=12)
        table.add_column("Valor")
        table.add_row("IP", shodan_info['ip'])
        table.add_row("Organización", shodan_info['org'])
        table.add_row("País", shodan_info['country'])
        table.add_row("Puertos Abiertos", ", ".join(map(str, shodan_info['ports'])))
        table.add_row("Hostnames", ", ".join(shodan_info['hostnames']))
        console.print(table)
        
        return shodan_info
    except Exception as e:
        console.print(f"[bold red]Error al obtener información de Shodan:[/bold red] {e}")
        return {"error": f"Error al obtener información de Shodan: {e}"}

# Función para obtener registros DNS
def get_dns_records(domain):
    try:
        resolver = dns.resolver.Resolver()
        a_records = resolver.resolve(domain, 'A')
        mx_records = resolver.resolve(domain, 'MX')
        ns_records = resolver.resolve(domain, 'NS')
        
        dns_info = {
            "A_records": sorted([str(ip) for ip in a_records]),
            "MX_records": sorted([str(mx.exchange) for mx in mx_records]),
            "NS_records": sorted([str(ns.target) for ns in ns_records])
        }
        
        # Mostrar los registros DNS en una tabla con rich
        table = Table(title="Registros DNS", show_header=True, header_style="bold cyan")
        table.add_column("Tipo de Registro", style="dim", width=12)
        table.add_column("Valor")
        table.add_row("A Records", ", ".join(dns_info['A_records']))
        table.add_row("MX Records", ", ".join(dns_info['MX_records']))
        table.add_row("NS Records", ", ".join(dns_info['NS_records']))
        console.print(table)
        
        return dns_info
    except Exception as e:
        console.print(f"[bold red]Error al obtener registros DNS:[/bold red] {e}")
        return {"error": f"Error al obtener registros DNS: {e}"}

# Función para obtener subdominios de SecurityTrails
def get_securitytrails_subdomains(api_key, domain):
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {'APIKEY': api_key}
        response = requests.get(url, headers=headers)
        data = response.json()
        subdomains = sorted(data.get('subdomains', []))
        
        # Agregar el dominio principal a la lista de subdominios
        if domain not in subdomains:
            subdomains.append(domain)
        
        # Obtener IPs para los subdominios
        subdomains_with_ips = []
        for subdomain in subdomains:
            full_domain = f"{subdomain}.{domain}" if subdomain != domain else domain
            try:
                ip = socket.gethostbyname(full_domain)
                subdomains_with_ips.append({"subdomain": full_domain, "ip": ip})
            except socket.gaierror:
                subdomains_with_ips.append({"subdomain": full_domain, "ip": "No encontrada"})
        
        # Mostrar los subdominios en una tabla con rich
        table = Table(title="Subdominios (SecurityTrails)", show_header=True, header_style="bold green")
        table.add_column("Subdominio")
        table.add_column("IP")
        for item in subdomains_with_ips:
            table.add_row(item["subdomain"], item["ip"])
        console.print(table)
        
        return subdomains_with_ips
    except Exception as e:
        console.print(f"[bold red]Error al obtener subdominios de SecurityTrails:[/bold red] {e}")
        return f"Error al obtener subdominios de SecurityTrails: {e}"

# Función para consultar Netlas API
def get_netlas_info(api_key, domain):
    try:
        params = {
            'q': domain,
            'source_type': 'include',
            'start': 0,
            'fields': '*'
        }
        headers = {
            'X-API-Key': api_key
        }

        response = requests.get("https://app.netlas.io/api/domains/", params=params, headers=headers)
        data = response.json()
        
        # Limpiar y organizar los datos
        cleaned_data = {
            "took": data.get("took", 0),
            "timed_out": data.get("timed_out", False),
            "items": []
        }
        
        if data.get('items'):
            table = Table(title="Netlas Results", show_header=True, header_style="bold purple")
            table.add_column("Campo")
            table.add_column("Valor")
            
            # Solo tomar el primer item para mostrar en la tabla
            first_item = data['items'][0]
            cleaned_item = {}
            
            for key, value in first_item.items():
                if key not in ['_shards', 'timed_out', 'took']:
                    cleaned_item[key] = value
                    
                    # Mostrar solo los primeros 100 caracteres para valores largos
                    display_value = str(value)
                    if len(display_value) > 100:
                        display_value = display_value[:100] + "..."
                    table.add_row(key, display_value)
            
            cleaned_data["items"].append(cleaned_item)
            console.print(table)
        
        return cleaned_data
    except Exception as e:
        console.print(f"[bold red]Error al consultar Netlas:[/bold red] {e}")
        return {"error": f"Error al consultar Netlas: {e}"}

# Función para obtener resultados de Google Dorks
def get_google_dorks(domain, google_api_key, google_cse_id):
    dorks = [
        f"site:{domain} filetype:pdf",
        f"site:{domain} filetype:doc OR filetype:docx",
        f"site:{domain} filetype:xls OR filetype:xlsx",
        f"site:{domain} filetype:ppt OR filetype:pptx",
        f"site:{domain} filetype:txt",
        f"site:{domain} filetype:log",
        f"site:{domain} filetype:conf",
        f"site:{domain} filetype:bak",
        f"site:{domain} filetype:jpg OR filetype:jpeg OR filetype:png OR filetype:gif",
        f"site:{domain} filetype:xml",
        f"site:{domain} filetype:csv",
        f"site:{domain} filetype:zip",
        f"site:{domain} filetype:rar",
        f"site:{domain} filetype:sql",
        f"site:{domain} filetype:php OR filetype:asp OR filetype:aspx OR filetype:js",
        f"site:{domain} intitle:'index of'",
        f"site:{domain} inurl:/uploads/",
        f"site:{domain} filetype:ini",
        f"site:{domain} filetype:pem OR filetype:cer OR filetype:crt",
        f"site:{domain} filetype:ova OR filetype:ovf",
        f"site:{domain} filetype:vsd OR filetype:vsdx",
        f"site:{domain} filetype:java OR filetype:py OR filetype:cpp",
        f"site:{domain} filetype:cfg OR filetype:config",
        f"site:{domain} filetype:md OR filetype:rst",
        f"site:{domain} filetype:psd OR filetype:ai",
        f"site:{domain} -www -shop -share -ir -mfa",
        f"site:{domain} ext:php inurl:?",
        f"site:{domain} inurl:api | site:*/rest | site:*/v1 | site:*/v2 | site:*/v3",
        f'site:"{domain}" ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json',
        f"inurl:conf | inurl:env | inurl:cgi | inurl:bin | inurl:etc | inurl:root | inurl:sql | inurl:backup | inurl:admin | inurl:php site:{domain}",
        f'inurl:"error" | intitle:"exception" | intitle:"failure" | intitle:"server at" | inurl:exception | "database error" | "SQL syntax" | "undefined index" | "unhandled exception" | "stack trace" site:{domain}',
        f"inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:& site:{domain}",
        f"inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:ret= | inurl:r2= | inurl:page= inurl:& inurl:http site:{domain}",
        f"inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:& site:{domain}",
        f"inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain=  | inurl:page= inurl:& site:{domain}",
        f"inurl:include | inurl:dir | inurl:detail= | inurl:file= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:& site:{domain}",
        f"inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read=  | inurl:ping= inurl:& site:{domain}",
        f'site:{domain} "choose file"',
        f'inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer site:"{domain}"',
        f"inurl:login | inurl:signin | intitle:login | intitle:signin | inurl:secure site:{domain}",
        f"inurl:test | inurl:env | inurl:dev | inurl:staging | inurl:sandbox | inurl:debug | inurl:temp | inurl:internal | inurl:demo site:{domain}",
        f"site:{domain} ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx",
        f'site:{domain} intext:"confidential" | intext:"Not for Public Release" | intext:"internal use only" | intext:"do not distribute"',
        f"inurl:email= | inurl:phone= | inurl:password= | inurl:secret= inurl:& site:{domain}",
        f"inurl:/content/usergenerated | inurl:/content/dam | inurl:/jcr:content | inurl:/libs/granite | inurl:/etc/clientlibs | inurl:/content/geometrixx | inurl:/bin/wcm | inurl:/crx/de site:{domain}",
        f'site:openbugbounty.org inurl:reports intext:"{domain}"',
        f'site:groups.google.com "{domain}"',
        f'site:pastebin.com "{domain}"',
        f'site:jsfiddle.net "{domain}"',
        f'site:codebeautify.org "{domain}"',
        f'site:codepen.io "{domain}"',
        f'site:s3.amazonaws.com "{domain}"',
        f'site:blob.core.windows.net "{domain}"',
        f'site:googleapis.com "{domain}"',
        f'site:drive.google.com "{domain}"',
        f'site:dev.azure.com "{domain}"',
        f'site:onedrive.live.com "{domain}"',
        f'site:digitaloceanspaces.com "{domain}"',
        f'site:sharepoint.com "{domain}"',
        f'site:s3-external-1.amazonaws.com "{domain}"',
        f'site:s3.dualstack.us-east-1.amazonaws.com "{domain}"',
        f'site:dropbox.com/s "{domain}"',
        f'site:box.com/s "{domain}"',
        f'site:docs.google.com inurl:"/d/" "{domain}"',
        f'site:jfrog.io "{domain}"',
        f'site:firebaseio.com "{domain}"',
        f'site:{domain} inurl:/wp-admin/admin-ajax.php',
        f'site:{domain} intext:"Powered by" & intext:Drupal & inurl:user',
        f'site:{domain} inurl:/joomla/login',
        f'site:{domain} inurl:/security.txt "bounty"',
        f'site:{domain} inurl:/server-status apache',
    ]
    
    results = {}
    for dork in dorks:
        try:
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                "q": dork,
                "key": google_api_key,
                "cx": google_cse_id,
                "num": 10
            }
            response = requests.get(url, params=params)
            data = response.json()
            search_results = [item.get("link") for item in data.get("items", [])]
            cleaned_results = list(set(search_results))
            cleaned_results = [url for url in cleaned_results if url and url.startswith("http")]
            results[dork] = cleaned_results
        except Exception as e:
            results[dork] = f"Error al buscar con el dork '{dork}': {e}"
    return results

# Función para buscar fugas de información en ProxyNova
def find_leaks_proxynova(domain, proxy=None, number=10):
    url = f"https://api.proxynova.com/comb?query={domain}"
    headers = {'User-Agent': 'curl'}
    session = requests.session()

    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}

    response = session.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        data = json.loads(response.text)
        total_results = data.get("count", 0)
        console.print(f"[bold magenta][*] Found {total_results} different records in database[/bold magenta]")

        lines = data.get("lines", [])[:number]
        table = Table(title="Leak Results")
        table.add_column("Record", style="cyan")
        for line in lines:
            table.add_row(line)
        console.print(table)
        return lines
    else:
        console.print(f"[bold red][!] Failed to fetch results from ProxyNova. Status code: {response.status_code}[/bold red]")
        return []

# Función para descargar archivos encontrados con Google Dorks
def download_files_from_dorks(google_dorks_results, download_folder="downloads"):
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
    
    for dork, results in google_dorks_results.items():
        if isinstance(results, list):
            console.print(f"\n[bold green][+] Descargando archivos para el dork:[/bold green] {dork}")
            for url in results:
                try:
                    response = requests.get(url, stream=True)
                    if response.status_code == 200:
                        file_name = os.path.join(download_folder, url.split("/")[-1])
                        with open(file_name, "wb") as file:
                            for chunk in response.iter_content(chunk_size=8192):
                                file.write(chunk)
                        console.print(f"[bold green][+] Descargado:[/bold green] {file_name}")
                    else:
                        console.print(f"[bold red][-] Error al descargar {url}: Código {response.status_code}[/bold red]")
                except Exception as e:
                    console.print(f"[bold red][-] Error al descargar {url}: {e}[/bold red]")

# Función para consultar Hunter.how API (versión simplificada)
# Función para consultar Hunter.how API (versión corregida según el formato de respuesta)
def query_hunterhow(domain, api_key):
    try:
        query = f'domain="{domain}"'
        encoded_query = base64.urlsafe_b64encode(query.encode("utf-8")).decode('ascii')
        page = 1
        page_size = 10
        today = datetime.today().strftime('%Y-%m-%d')
        
        url = (
            f"https://api.hunter.how/search?"
            f"api-key={api_key}&query={encoded_query}&"
            f"page={page}&page_size={page_size}&"
            f"start_time={today}&end_time={today}"
        )
        
        response = requests.get(url)
        data = response.json()
        
        # Limpiar y organizar los resultados según el formato mostrado
        cleaned_data = {
            "code": data.get("code", 0),
            "message": data.get("message", ""),
            "limits": {
                "per_day_search_limit": data.get("data", {}).get("per_day_search_limit", 0),
                "per_day_search_count": data.get("data", {}).get("per_day_search_count", 0),
                "per_day_api_pull_limit": data.get("data", {}).get("per_day_api_pull_limit", 0),
                "per_day_api_pull_count": data.get("data", {}).get("per_day_api_pull_count", 0)
            },
            "results": []
        }
        
        if data.get('data', {}).get('list'):
            table = Table(title="Hunter.how Results", show_header=True, header_style="bold yellow")
            table.add_column("Domain")
            table.add_column("IP")
            table.add_column("Port")
            
            for item in data['data']['list']:
                cleaned_item = {
                    "domain": item.get('domain', 'N/A'),
                    "ip": item.get('ip', 'N/A'),
                    "port": item.get('port', 'N/A')
                }
                cleaned_data["results"].append(cleaned_item)
                
                table.add_row(
                    cleaned_item["domain"],
                    cleaned_item["ip"],
                    str(cleaned_item["port"])
                )
            console.print(table)
        
        return cleaned_data
    except Exception as e:
        console.print(f"[bold red]Error al consultar Hunter.how:[/bold red] {e}")
        return {"error": f"Error al consultar Hunter.how: {e}"}

# Función para realizar el análisis completo de un dominio
def analyze_domain(domain, api_keys):
    # Obtener la IP del dominio
    ip = get_ip_from_domain(domain)
    if 'Error' in ip:
        return {"error": ip}
    
    # Obtener subdominios desde SecurityTrails
    securitytrails_subdomains = get_securitytrails_subdomains(api_keys["securitytrails"], domain)
    
    # Obtener subdominios desde crt.sh
    crtsh_subdomains, crtsh_wildcards = get_crtsh_subdomains(domain)
    
    # Obtener información de Shodan usando la IP
    shodan_info = get_shodan_info(api_keys["shodan"], ip)
    
    # Obtener registros DNS usando DNSPython
    dns_info = get_dns_records(domain)
    
    # Obtener resultados de búsqueda con Google Dorks
    google_dorks_results = clean_text(get_google_dorks(domain, api_keys["google_api_key"], api_keys["google_cse_id"]))

    # Buscar fugas de información en ProxyNova
    leaks = clean_text(find_leaks_proxynova(domain))

    # Consultar Netlas
    netlas_info = clean_text(get_netlas_info(api_keys["netlas"], domain))

    # Consultar Hunter.how (versión simplificada)
    hunterhow_info = query_hunterhow(domain, api_keys.get("hunterhow", ""))

    # Descargar archivos encontrados con Google Dorks
    download_files_from_dorks(google_dorks_results)

    # Crear informe
    report = {
        "domain": domain,
        "ip": ip,
        "subdomains": securitytrails_subdomains,
        "crtsh_subdomains": crtsh_subdomains,
        "crtsh_wildcards": crtsh_wildcards,
        "shodan_info": shodan_info,
        "dns_info": dns_info,
        "google_dorks": google_dorks_results,
        "leaks": leaks,
        "netlas_info": netlas_info,
        "hunterhow_info": hunterhow_info
    }
    
    return report

# Función para generar el informe HTML
def generate_html_report(report):
    html_template = """
    <html>
    <head>
        <title>RECON REPORT - {{ report['domain'] }}</title>
        <style>
            :root {
                --hacker-green: #00ff00;
                --dark-bg: #121212;
                --darker-bg: #0a0a0a;
                --light-text: #e0e0e0;
                --accent-blue: #00a8ff;
                --accent-purple: #9c27b0;
            }
            body {
                font-family: 'Courier New', monospace;
                margin: 0;
                padding: 20px;
                background-color: var(--dark-bg);
                color: var(--light-text);
                line-height: 1.6;
            }
            .header {
                background-color: var(--darker-bg);
                color: var(--hacker-green);
                padding: 20px;
                border: 1px solid var(--hacker-green);
                margin-bottom: 20px;
                text-shadow: 0 0 5px var(--hacker-green);
                position: relative;
                overflow: hidden;
            }
            .header::before {
                content: "";
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 2px;
                background: linear-gradient(90deg, transparent, var(--hacker-green), transparent);
                animation: scanline 2s linear infinite;
            }
            @keyframes scanline {
                0% { top: 0; }
                100% { top: 100%; }
            }
            h1 {
                margin: 0;
                font-size: 24px;
                letter-spacing: 2px;
            }
            h2 {
                color: var(--accent-blue);
                border-bottom: 1px solid var(--accent-blue);
                padding-bottom: 5px;
                margin-top: 30px;
                text-transform: uppercase;
                font-size: 18px;
            }
            h3 {
                color: var(--hacker-green);
                margin-top: 20px;
                font-size: 16px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 15px 0;
                border: 1px solid #333;
            }
            th {
                background-color: #1a1a1a;
                color: var(--hacker-green);
                text-align: left;
                padding: 12px;
                border: 1px solid #333;
                font-weight: bold;
                letter-spacing: 1px;
            }
            td {
                padding: 12px;
                border: 1px solid #333;
                color: var(--light-text);
            }
            tr:nth-child(even) {
                background-color: rgba(0, 255, 0, 0.03);
            }
            tr:hover {
                background-color: rgba(0, 255, 0, 0.1);
            }
            .success-badge {
                display: inline-block;
                background-color: rgba(0, 255, 0, 0.2);
                color: var(--hacker-green);
                padding: 8px 15px;
                border: 1px solid var(--hacker-green);
                font-size: 14px;
                margin: 10px 0;
                font-weight: bold;
                box-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
            }
            .info-box {
                background-color: rgba(0, 168, 255, 0.1);
                border-left: 4px solid var(--accent-blue);
                padding: 15px;
                margin: 15px 0;
                border-right: 1px solid rgba(0, 168, 255, 0.3);
            }
            .info-box strong {
                color: var(--accent-blue);
            }
            .divider {
                border-top: 1px dashed rgba(0, 255, 0, 0.3);
                margin: 20px 0;
            }
            a {
                color: var(--accent-blue);
                text-decoration: none;
                transition: all 0.3s;
            }
            a:hover {
                color: var(--hacker-green);
                text-shadow: 0 0 5px var(--hacker-green);
            }
            .terminal {
                background-color: rgba(0, 0, 0, 0.5);
                border: 1px solid var(--hacker-green);
                padding: 15px;
                margin: 15px 0;
                position: relative;
            }
            .terminal::before {
                content: ">_";
                position: absolute;
                top: -10px;
                left: 10px;
                background: var(--dark-bg);
                padding: 0 5px;
                color: var(--hacker-green);
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1 class="glitch" data-text="RECON REPORT ACTIVE">RECON REPORT ACTIVE</h1>
        </div>

        <div class="info-box">
            <p><strong>TARGET</strong><br>{{ report['domain'] }}</p>
            <p><strong>IP ADDRESS</strong><br>{{ report['ip'] }}</p>
            <p><strong>SCAN DATE</strong><br>{{ datetime.now().strftime('%m/%d/%Y') }}</p>
        </div>

        <div class="divider"></div>

        <div class="success-badge">>> SCAN COMPLETED SUCCESSFULLY! <<</div>

        <div class="divider"></div>

        <h2>SUB-DOMAINS ANALYSIS</h2>

        <div class="terminal">
            <h3>SecurityTrails Results</h3>
            <table>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Address</th>
                </tr>
                {% for subdomain in report['subdomains'] %}
                <tr>
                    <td>{{ subdomain['subdomain'] }}</td>
                    <td>{{ subdomain['ip'] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>

        {% if report['crtsh_subdomains'] %}
        <div class="terminal">
            <h3>crt.sh Results</h3>
            <table>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Address</th>
                </tr>
                {% for subdomain in report['crtsh_subdomains'] %}
                <tr>
                    <td>{{ subdomain['subdomain'] }}</td>
                    <td>{{ subdomain['ip'] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if report['crtsh_wildcards'] %}
        <div class="terminal">
            <h3>Wildcard Subdomains (crt.sh)</h3>
            <table>
                <tr>
                    <th>Subdomain</th>
                </tr>
                {% for wildcard in report['crtsh_wildcards'] %}
                <tr>
                    <td>{{ wildcard }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        <h2>DNS INFORMATION</h2>
        <div class="terminal">
            <table>
                <tr>
                    <th>Record Type</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>A Records</td>
                    <td>{{ report['dns_info']['A_records'] | join(", ") }}</td>
                </tr>
                <tr>
                    <td>MX Records</td>
                    <td>{{ report['dns_info']['MX_records'] | join(", ") }}</td>
                </tr>
                <tr>
                    <td>NS Records</td>
                    <td>{{ report['dns_info']['NS_records'] | join(", ") }}</td>
                </tr>
            </table>
        </div>

        {% if report['shodan_info'] and not report['shodan_info'].get('error') %}
        <h2>SHODAN RESULTS</h2>
        <div class="terminal">
            <table>
                <tr>
                    <th>Field</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>IP</td>
                    <td>{{ report['shodan_info']['ip'] }}</td>
                </tr>
                <tr>
                    <td>Organization</td>
                    <td>{{ report['shodan_info']['org'] }}</td>
                </tr>
                <tr>
                    <td>Country</td>
                    <td>{{ report['shodan_info']['country'] }}</td>
                </tr>
                <tr>
                    <td>Open Ports</td>
                    <td>{{ report['shodan_info']['ports'] | join(", ") }}</td>
                </tr>
                <tr>
                    <td>Hostnames</td>
                    <td>{{ report['shodan_info']['hostnames'] | join(", ") }}</td>
                </tr>
            </table>
        </div>
        {% endif %}

        {% if report['netlas_info'] and not report['netlas_info'].get('error') and report['netlas_info']['items'] %}
        <h2>NETLAS RESULTS</h2>
        <div class="terminal">
            <table>
                <tr>
                    <th>Field</th>
                    <th>Value</th>
                </tr>
                {% for key, value in report['netlas_info']['items'][0].items() %}
                    {% if key not in ['_shards', 'timed_out', 'took'] and value %}
                    <tr>
                        <td>{{ key }}</td>
                        <td>
                            {% if value is mapping %}
                                {% for k, v in value.items() %}
                                    <strong>{{ k|replace("'","")|replace("[","")|replace("]","")|replace("@","") }}:</strong> 
                                    {{ v|replace("'","")|replace("[","")|replace("]","")|replace("@","") }}<br>
                                {% endfor %}
                            {% elif value is iterable and value is not string %}
                                {{ value|join(", ")|replace("'","")|replace("[","")|replace("]","")|replace("@","") }}
                            {% else %}
                                {{ value|replace("'","")|replace("[","")|replace("]","")|replace("@","") }}
                            {% endif %}
                        </td>
                    </tr>
                    {% endif %}
                {% endfor %}
            </table>
        </div>
        {% endif %}

{% if report['hunterhow_info'] and not report['hunterhow_info'].get('error') %}
<h2>HUNTER.HOW RESULTS</h2>
<div class="terminal">
    {% if report['hunterhow_info']['results'] %}
        <table>
            <tr>
                <th>Domain</th>
                <th>IP</th>
                <th>Port</th>
            </tr>
            {% for item in report['hunterhow_info']['results'] %}
            <tr>
                <td>{{ item['domain'] }}</td>
                <td>{{ item['ip'] }}</td>
                <td>{{ item['port'] }}</td>
            </tr>
            {% endfor %}
        </table>
        
        <div style="margin-top: 20px; color: var(--accent-blue);">
            <p><strong>API Usage:</strong> 
            {{ report['hunterhow_info']['limits']['per_day_search_count'] }}/{{ report['hunterhow_info']['limits']['per_day_search_limit'] }} searches today |
            {{ report['hunterhow_info']['limits']['per_day_api_pull_count'] }}/{{ report['hunterhow_info']['limits']['per_day_api_pull_limit'] }} API pulls today</p>
        </div>
    {% else %}
        <p>No results found in Hunter.how</p>
    {% endif %}
</div>
{% endif %}

        {% if report['google_dorks'] %}
        <h2>GOOGLE DORKS RESULTS</h2>
        <div class="terminal">
            {% for dork, results in report['google_dorks'].items() %}
                <h3>{{ dork }}</h3>
                {% if results is iterable and results is not string %}
                <table>
                    <tr>
                        <th>URL</th>
                    </tr>
                    {% for result in results %}
                    <tr>
                        <td><a href="{{ result }}" target="_blank">{{ result }}</a></td>
                    </tr>
                    {% endfor %}
                </table>
                {% else %}
                <p>{{ results }}</p>
                {% endif %}
            {% endfor %}
        </div>
        {% endif %}

        {% if report['leaks'] %}
        <h2>DATA LEAKS</h2>
        <div class="terminal">
            <table>
                <tr>
                    <th>Record</th>
                </tr>
                {% for leak in report['leaks'] %}
                <tr>
                    <td>{{ leak }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        <div class="divider"></div>
        <div style="text-align: center; color: var(--hacker-green); font-size: 12px;">
            [ RECON TOOL BY CREADPAG | {{ datetime.now().strftime('%Y') }} ]
        </div>
    </body>
    </html>
    """
    
    template = Template(html_template)
    html_content = template.render(report=clean_text(report), datetime=datetime)

    # Guardar el informe en un archivo HTML
    report_filename = f"recon_report_{report['domain']}.html"
    with open(report_filename, 'w', encoding='utf-8') as file:
        file.write(html_content)
    return report_filename

# Función principal
def main():
    # Imprimir banner de bienvenida
    print_hacker_banner()

    # Parsear los argumentos de la línea de comandos
    args = parse_args()

    domain = args.domain
    api_keys = {
        "shodan": "",
        "securitytrails": "",
        "google_api_key": "",
        "google_cse_id": "",
        "netlas": "",
        "hunterhow": ""
    }
    
    # Analizar el dominio
    report = analyze_domain(domain, api_keys)
    
    # Generar y guardar el informe HTML
    report_filename = generate_html_report(report)
    
    console.print(f"[bold green]Informe generado y guardado como '{report_filename}'[/bold green]")

if __name__ == "__main__":
    main()