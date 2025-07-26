import os
import sys
import requests
import json
import argparse
import socket
import dns.resolver
import urllib3
import subprocess
import base64
import time
from datetime import datetime
from jinja2 import Template
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from bs4 import BeautifulSoup
import pandas as pd

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
              subtitle="[blue]by CreadPag 2.0[/]",
              border_style="blue"))

# Función para manejar los argumentos de la línea de comandos
def parse_args():
    parser = argparse.ArgumentParser(description="Reconocimiento y análisis de dominios con herramientas hacker.")
    
    # Grupo para argumentos mutuamente excluyentes: -d o -l
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", type=str, help="Dominio único a analizar")
    group.add_argument("-l", "--list", type=str, help="Ruta a un archivo con una lista de dominios (uno por línea)")
    
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

# Función para obtener subdominios de crt.sh con manejo de reintentos
def get_crtsh_subdomains(domain):
    BASE_URL = "https://crt.sh/?q={}&output=json"
    subdomains = set()
    wildcardsubdomains = set()
    max_retries = 3
    initial_timeout = 30
    
    for attempt in range(max_retries):
        try:
            console.print(f"[bold yellow]Intentando obtener subdominios de crt.sh para {domain} (Intento {attempt + 1}/{max_retries})...[/bold yellow]")
            response = requests.get(BASE_URL.format(domain), timeout=initial_timeout + (attempt * 10)) 
            
            if response.ok:
                content = response.content.decode('UTF-8')
                jsondata = json.loads(content)
                for entry in jsondata:
                    name_value = entry['name_value']
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
                break
            else:
                console.print(f"[bold red]crt.sh respondió con código {response.status_code}. Reintentando...[/bold red]")
        except requests.exceptions.Timeout:
            console.print(f"[bold red]Tiempo de espera agotado al conectar con crt.sh. Reintentando...[/bold red]")
        except Exception as e:
            console.print(f"[bold red]Error al obtener subdominios de crt.sh:[/bold red] {e}. Reintentando...[/bold red]")
        
        if attempt < max_retries - 1:
            time.sleep(5 + (attempt * 5))

    subdomains_with_ips = []
    if subdomains:
        for subdomain in subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                subdomains_with_ips.append({"subdomain": subdomain, "ip": ip})
            except socket.gaierror:
                subdomains_with_ips.append({"subdomain": subdomain, "ip": "No encontrada"})

    if subdomains_with_ips:
        table = Table(title=f"Subdominios de crt.sh para {domain}", show_header=True, header_style="bold green")
        table.add_column("Subdominio")
        table.add_column("IP")
        for item in subdomains_with_ips:
            table.add_row(item["subdomain"], item["ip"])
        console.print(table)
    else:
        console.print(f"[bold yellow]No se encontraron subdominios estándar en crt.sh para {domain}.[/bold yellow]")

    if wildcardsubdomains:
        table = Table(title=f"Subdominios Wildcard de crt.sh para {domain}", show_header=True, header_style="bold yellow")
        table.add_column("Subdominio Wildcard")
        for wildcard in wildcardsubdomains:
            table.add_row(wildcard)
        console.print(table)
    else:
        console.print(f"[bold yellow]No se encontraron subdominios wildcard en crt.sh para {domain}.[/bold yellow]")

    return subdomains_with_ips, list(wildcardsubdomains)

# Función para obtener información de Shodan
def get_shodan_info(api_key, ip):
    try:
        if not api_key:
            console.print("[bold red]Advertencia: No se ha proporcionado la API Key de Shodan. Se omitirá la búsqueda en Shodan.[/bold red]")
            return {"error": "API Key de Shodan no proporcionada"}

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
        
        table = Table(title=f"Información de Shodan para {ip}", show_header=True, header_style="bold magenta")
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
        a_records = []
        mx_records = []
        ns_records = []

        try:
            a_records = resolver.resolve(domain, 'A')
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            console.print(f"[bold red]Error al obtener registros A de {domain}:[/bold red] {e}")

        try:
            mx_records = resolver.resolve(domain, 'MX')
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            console.print(f"[bold red]Error al obtener registros MX de {domain}:[/bold red] {e}")
            
        try:
            ns_records = resolver.resolve(domain, 'NS')
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            console.print(f"[bold red]Error al obtener registros NS de {domain}:[/bold red] {e}")
        
        dns_info = {
            "A_records": sorted([str(ip) for ip in a_records]),
            "MX_records": sorted([str(mx.exchange) for mx in mx_records]),
            "NS_records": sorted([str(ns.target) for ns in ns_records])
        }
        
        table = Table(title=f"Registros DNS para {domain}", show_header=True, header_style="bold cyan")
        table.add_column("Tipo de Registro", style="dim", width=12)
        table.add_column("Valor")
        table.add_row("A Records", ", ".join(dns_info['A_records']) if dns_info['A_records'] else "N/A")
        table.add_row("MX Records", ", ".join(dns_info['MX_records']) if dns_info['MX_records'] else "N/A")
        table.add_row("NS Records", ", ".join(dns_info['NS_records']) if dns_info['NS_records'] else "N/A")
        console.print(table)
        
        return dns_info
    except Exception as e:
        console.print(f"[bold red]Error general al obtener registros DNS:[/bold red] {e}")
        return {"error": f"Error general al obtener registros DNS: {e}"}

# Función para obtener subdominios de SecurityTrails
def get_securitytrails_subdomains(api_key, domain):
    try:
        if not api_key:
            console.print("[bold red]Advertencia: No se ha proporcionado la API Key de SecurityTrails. Se omitirá la búsqueda en SecurityTrails.[/bold red]")
            return {"error": "API Key de SecurityTrails no proporcionada"}

        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {'APIKEY': api_key}
        response = requests.get(url, headers=headers)
        data = response.json()

        if response.status_code != 200:
            console.print(f"[bold red]Error en SecurityTrails: {data.get('message', 'Error desconocido')}[/bold red]")
            return {"error": f"SecurityTrails error: {data.get('message', 'Error desconocido')}"}

        subdomains = sorted(data.get('subdomains', []))
        
        if domain not in subdomains:
            subdomains.append(domain)
        
        subdomains_with_ips = []
        for subdomain in subdomains:
            full_domain = f"{subdomain}.{domain}" if subdomain != domain else domain
            try:
                ip = socket.gethostbyname(full_domain)
                subdomains_with_ips.append({"subdomain": full_domain, "ip": ip})
            except socket.gaierror:
                subdomains_with_ips.append({"subdomain": full_domain, "ip": "No encontrada"})
        
        if subdomains_with_ips:
            table = Table(title=f"Subdominios (SecurityTrails) para {domain}", show_header=True, header_style="bold green")
            table.add_column("Subdominio")
            table.add_column("IP")
            for item in subdomains_with_ips:
                table.add_row(item["subdomain"], item["ip"])
            console.print(table)
            return {"data": subdomains_with_ips}
        else:
            console.print(f"[bold yellow]No se encontraron subdominios en SecurityTrails para {domain}.[/bold yellow]")
            return {"data": []}
    except Exception as e:
        console.print(f"[bold red]Error al obtener subdominios de SecurityTrails:[/bold red] {e}")
        return {"error": f"Error al obtener subdominios de SecurityTrails: {e}"}

# Función para consultar Netlas API
def get_netlas_info(api_key, domain):
    try:
        if not api_key:
            console.print("[bold red]Advertencia: No se ha proporcionado la API Key de Netlas. Se omitirá la búsqueda en Netlas.[/bold red]")
            return {"error": "API Key de Netlas no proporcionada"}

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
        
        if response.status_code != 200:
            console.print(f"[bold red]Error en Netlas: {data.get('message', 'Error desconocido')}[/bold red]")
            return {"error": f"Netlas error: {data.get('message', 'Error desconocido')}"}

        cleaned_data = {
            "took": data.get("took", 0),
            "timed_out": data.get("timed_out", False),
            "items": data.get("items", [])
        }
        
        if cleaned_data.get('items'):
            table = Table(title=f"Netlas Results para {domain}", show_header=True, header_style="bold purple")
            table.add_column("Campo")
            table.add_column("Valor")
            
            first_item = cleaned_data['items'][0]
            
            for key, value in first_item.items():
                if key not in ['_shards', 'timed_out', 'took']:
                    display_value = str(value)
                    if len(display_value) > 100:
                        display_value = display_value[:100] + "..."
                    table.add_row(key, display_value)
            
            console.print(table)
        else:
            console.print(f"[bold yellow]No se encontraron resultados en Netlas para {domain}.[/bold yellow]")
        
        return cleaned_data
    except Exception as e:
        console.print(f"[bold red]Error al consultar Netlas:[/bold red] {e}")
        return {"error": f"Error al consultar Netlas: {e}"}

# Función para obtener resultados de Google Dorks usando la API de Google
def get_google_dorks_api(domain, google_api_key, google_cse_id):
    if not google_api_key or not google_cse_id:
        console.print("[bold red]Advertencia: No se han proporcionado las API Keys de Google CSE. Se omitirá la búsqueda de Google Dorks con API.[/bold red]")
        return {"error": "API Keys de Google CSE no proporcionadas"}

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
        f"inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:r2= | inurl:page= inurl:& inurl:http site:{domain}",
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
            console.print(f"[bold green]Buscando con dork (API de Google) para {domain}:[/bold green] {dork}")
            response = requests.get(url, params=params)
            data = response.json()
            search_results = [item.get("link") for item in data.get("items", [])]
            cleaned_results = list(set(search_results))
            cleaned_results = [url for url in cleaned_results if url and url.startswith("http")]
            results[dork] = cleaned_results
            
            time.sleep(1) 
        except Exception as e:
            results[dork] = f"Error al buscar con el dork '{dork}': {e}"
            console.print(f"[bold red]Error al usar Google API para el dork '{dork}' para {domain}:[/bold red] {e}")
    return results

# Función para obtener resultados de Google Dorks mediante web scraping (SIN API)
def get_google_dorks_scraper(domain):
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
        f"inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:r2= | inurl:page= inurl:& inurl:http site:{domain}",
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
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
    }

    for dork in dorks:
        try:
            encoded_dork = requests.utils.quote(dork)
            url = f"https://www.google.com/search?q={encoded_dork}"
            
            console.print(f"[bold yellow]Buscando con dork (sin API) para {domain}:[/bold yellow] {dork}")
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            
            links = []
            for g in soup.find_all('div', class_='g'):
                a_tag = g.find('a')
                if a_tag and 'href' in a_tag.attrs:
                    link = a_tag['href']
                    if link and link.startswith("http") and domain in link:
                        links.append(link)
            
            cleaned_results = list(set(links))
            results[dork] = cleaned_results
            
            time.sleep(2) 

        except requests.exceptions.HTTPError as err:
            console.print(f"[bold red]Error HTTP al buscar con el dork '{dork}' para {domain}:[/bold red] {err}")
            if "429" in str(err) or "503" in str(err):
                console.print("[bold red]Posiblemente bloqueado por Google. Intenta más tarde o con un proxy.[/bold red]")
            results[dork] = f"Error HTTP: {err}"
        except requests.exceptions.ConnectionError as err:
            console.print(f"[bold red]Error de conexión al buscar con el dork '{dork}' para {domain}:[/bold red] {err}")
            results[dork] = f"Error de conexión: {err}"
        except requests.exceptions.Timeout:
            console.print(f"[bold red]Tiempo de espera agotado al buscar con el dork '{dork}' para {domain}.[/bold red]")
            results[dork] = f"Tiempo de espera agotado."
        except Exception as e:
            results[dork] = f"Error al buscar con el dork '{dork}': {e}"
            console.print(f"[bold red]Error desconocido al buscar con el dork '{dork}' para {domain}:[/bold red] {e}")
            
    return results


# Función para buscar fugas de información en ProxyNova
def find_leaks_proxynova(domain, proxy=None, number=10):
    url = f"https://api.proxynova.com/comb?query={domain}"
    headers = {'User-Agent': 'curl'}
    session = requests.session()

    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}

    try:
        response = session.get(url, headers=headers, verify=False)

        if response.status_code == 200:
            data = json.loads(response.text)
            total_results = data.get("count", 0)
            console.print(f"[bold magenta][*] Found {total_results} different records in database for {domain}[/bold magenta]")

            lines = data.get("lines", [])[:number]
            table = Table(title=f"Leak Results for {domain}")
            table.add_column("Record", style="cyan")
            for line in lines:
                table.add_row(line)
            console.print(table)
            return lines
        else:
            console.print(f"[bold red][!] Failed to fetch results from ProxyNova for {domain}. Status code: {response.status_code}[/bold red]")
            return []
    except Exception as e:
        console.print(f"[bold red][!] Error al buscar fugas en ProxyNova for {domain}: {e}[/bold red]")
        return []

# Función para descargar archivos encontrados con Google Dorks
def download_files_from_dorks(google_dorks_results, download_folder): # Modificado para usar download_folder
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
    
    for dork, results in google_dorks_results.items():
        if isinstance(results, list):
            console.print(f"\n[bold green][+] Descargando archivos para el dork:[/bold green] {dork}")
            for url in results:
                try:
                    if not url.startswith('http'):
                        console.print(f"[bold yellow][-] Saltando URL no válida (no HTTP):[/bold yellow] {url}")
                        continue

                    response = requests.get(url, stream=True, timeout=10)
                    if response.status_code == 200:
                        file_name_part = url.split("/")[-1].split('?')[0].split('#')[0]
                        if not file_name_part:
                            file_name_part = "downloaded_file"
                        
                        file_name = os.path.join(download_folder, file_name_part)
                        
                        counter = 1
                        original_file_name = file_name
                        while os.path.exists(file_name):
                            name, ext = os.path.splitext(original_file_name)
                            file_name = f"{name}_{counter}{ext}"
                            counter += 1

                        with open(file_name, "wb") as file:
                            for chunk in response.iter_content(chunk_size=8192):
                                file.write(chunk)
                        console.print(f"[bold green][+] Descargado:[/bold green] {file_name}")
                    else:
                        console.print(f"[bold red][-] Error al descargar {url}: Código {response.status_code}[/bold red]")
                except requests.exceptions.Timeout:
                    console.print(f"[bold red][-] Tiempo de espera agotado al descargar {url}.[/bold red]")
                except Exception as e:
                    console.print(f"[bold red][-] Error al descargar {url}: {e}[/bold red]")

# Función para consultar Hunter.how API
def query_hunterhow(domain, api_key):
    try:
        if not api_key:
            console.print("[bold red]Advertencia: No se ha proporcionado la API Key de Hunter.how. Se omitirá la búsqueda en Hunter.how.[/bold red]")
            return {"error": "API Key de Hunter.how no proporcionada"}

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
        
        if response.status_code != 200:
            console.print(f"[bold red]Error en Hunter.how: {data.get('message', 'Error desconocido')}[/bold red]")
            return {"error": f"Hunter.how error: {data.get('message', 'Error desconocido')}"}

        cleaned_data = {
            "code": data.get("code", 0),
            "message": data.get("message", ""),
            "limits": {
                "per_day_search_limit": data.get("data", {}).get("per_day_search_limit", 0),
                "per_day_search_count": data.get("data", {}).get("per_day_search_count", 0),
                "per_day_api_pull_limit": data.get("data", {}).get("per_day_api_pull_limit", 0),
                "per_day_api_pull_count": data.get("data", {}).get("per_day_api_pull_count", 0)
            },
            "results": data.get("data", {}).get('list', [])
        }
        
        if cleaned_data.get('results'):
            table = Table(title=f"Hunter.how Results para {domain}", show_header=True, header_style="bold yellow")
            table.add_column("Domain")
            table.add_column("IP")
            table.add_column("Port")
            
            for item in cleaned_data['results']:
                table.add_row(
                    item.get("domain", "N/A"),
                    item.get("ip", "N/A"),
                    str(item.get("port", "N/A"))
                )
            console.print(table)
        else:
            console.print(f"[bold yellow]No se encontraron resultados en Hunter.how para {domain}.[/bold yellow]")
        
        return cleaned_data
    except Exception as e:
        console.print(f"[bold red]Error al consultar Hunter.how:[/bold red] {e}")
        return {"error": f"Error al consultar Hunter.how: {e}"}

# Función para generar el informe Excel
def generate_excel_report(report, output_folder):
    excel_filename = os.path.join(output_folder, f"recon_report_{report['domain']}.xlsx")
    
    try:
        with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
            # Hoja: General Info
            general_info = {
                "Campo": ["Dominio", "IP"],
                "Valor": [report['domain'], report['ip']]
            }
            pd.DataFrame(general_info).to_excel(writer, sheet_name='General Info', index=False)

            # Hoja: DNS Records
            dns_data = []
            if report['dns_info'] and not report['dns_info'].get('error'):
                if report['dns_info']['A_records']:
                    dns_data.append({"Tipo de Registro": "A Records", "Valor": ", ".join(report['dns_info']['A_records'])})
                if report['dns_info']['MX_records']:
                    dns_data.append({"Tipo de Registro": "MX Records", "Valor": ", ".join(report['dns_info']['MX_records'])})
                if report['dns_info']['NS_records']:
                    dns_data.append({"Tipo de Registro": "NS Records", "Valor": ", ".join(report['dns_info']['NS_records'])})
            pd.DataFrame(dns_data).to_excel(writer, sheet_name='DNS Records', index=False)

            # Hoja: SecurityTrails Subdomains
            if report['subdomains'] and not report['subdomains'].get('error') and report['subdomains'].get('data'):
                pd.DataFrame(report['subdomains']['data']).to_excel(writer, sheet_name='SecurityTrails Subdomains', index=False)
            else:
                pd.DataFrame([{"Subdominio": "No data", "IP": "No data"}]).to_excel(writer, sheet_name='SecurityTrails Subdomains', index=False)

            # Hoja: Crt.sh Subdomains
            if report['crtsh_subdomains']:
                pd.DataFrame(report['crtsh_subdomains']).to_excel(writer, sheet_name='Crt.sh Subdomains', index=False)
            else:
                pd.DataFrame([{"Subdominio": "No data", "IP": "No data"}]).to_excel(writer, sheet_name='Crt.sh Subdomains', index=False)

            # Hoja: Crt.sh Wildcards
            if report['crtsh_wildcards']:
                pd.DataFrame({"Wildcard Subdomain": report['crtsh_wildcards']}).to_excel(writer, sheet_name='Crt.sh Wildcards', index=False)
            else:
                pd.DataFrame([{"Wildcard Subdomain": "No data"}]).to_excel(writer, sheet_name='Crt.sh Wildcards', index=False)

            # Hoja: Shodan Info
            shodan_data = []
            if report['shodan_info'] and not report['shodan_info'].get('error'):
                shodan_data.append({"Campo": "IP", "Valor": report['shodan_info'].get('ip', 'N/A')})
                shodan_data.append({"Campo": "Organización", "Valor": report['shodan_info'].get('org', 'N/A')})
                shodan_data.append({"Campo": "País", "Valor": report['shodan_info'].get('country', 'N/A')})
                shodan_data.append({"Campo": "Puertos Abiertos", "Valor": ", ".join(map(str, report['shodan_info'].get('ports', [])))})
                shodan_data.append({"Campo": "Hostnames", "Valor": ", ".join(report['shodan_info'].get('hostnames', []))})
            pd.DataFrame(shodan_data).to_excel(writer, sheet_name='Shodan Info', index=False)

            # Hoja: Netlas Info
            if report['netlas_info'] and not report['netlas_info'].get('error') and report['netlas_info'].get('items'):
                # Convertir los items en un formato plano si son muy anidados
                flat_netlas_data = []
                for item in report['netlas_info']['items']:
                    flat_item = {}
                    for k, v in item.items():
                        if isinstance(v, (dict, list)):
                            flat_item[k] = json.dumps(v) # Convertir dicts/lists a string JSON
                        else:
                            flat_item[k] = v
                    flat_netlas_data.append(flat_item)
                pd.DataFrame(flat_netlas_data).to_excel(writer, sheet_name='Netlas Info', index=False)
            else:
                 pd.DataFrame([{"Info": "No se encontraron resultados en Netlas o hubo un error."}]).to_excel(writer, sheet_name='Netlas Info', index=False)


            # Hoja: Hunter.how Info
            if report['hunterhow_info'] and not report['hunterhow_info'].get('error') and report['hunterhow_info'].get('results'):
                pd.DataFrame(report['hunterhow_info']['results']).to_excel(writer, sheet_name='Hunter.how Info', index=False)
            else:
                pd.DataFrame([{"Domain": "No data", "IP": "No data", "Port": "No data"}]).to_excel(writer, sheet_name='Hunter.how Info', index=False)

            # Hoja: Google Dorks
            dorks_data = []
            if report['google_dorks']:
                for dork, urls in report['google_dorks'].items():
                    if isinstance(urls, list):
                        for url in urls:
                            dorks_data.append({"Dork Query": dork, "Found URL": url})
                    else: # Handle error messages
                        dorks_data.append({"Dork Query": dork, "Found URL": urls})
            pd.DataFrame(dorks_data).to_excel(writer, sheet_name='Google Dorks', index=False)

            # Hoja: Data Leaks
            if report['leaks']:
                pd.DataFrame({"Leak Record": report['leaks']}).to_excel(writer, sheet_name='Data Leaks', index=False)
            else:
                pd.DataFrame([{"Leak Record": "No se encontraron fugas de información."}]).to_excel(writer, sheet_name='Data Leaks', index=False)

        console.print(f"[bold green]Informe Excel generado y guardado como '{excel_filename}'[/bold green]")
        return excel_filename
    except Exception as e:
        console.print(f"[bold red]Error al generar el informe Excel: {e}[/bold red]")
        return None

# Función para generar el informe HTML
def generate_html_report(report, output_folder):
    html_template = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RECON REPORT - {{ report['domain'] }}</title>
        <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&family=Share+Tech+Mono&display=swap" rel="stylesheet">
        <style>
            :root {
                --hacker-green: #00ff00;
                --dark-bg: #1a1a1a;
                --darker-bg: #0d0d0d;
                --light-text: #e0e0e0;
                --accent-blue: #00aaff;
                --code-bg: #2b2b2b;
                --border-color: #333333;
            }
            body {
                font-family: 'Share Tech Mono', monospace;
                margin: 0;
                padding: 20px;
                background-color: var(--dark-bg);
                color: var(--light-text);
                line-height: 1.6;
                overflow-x: hidden;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: var(--darker-bg);
                border: 1px solid var(--border-color);
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.1), 0 0 15px rgba(0, 170, 255, 0.1);
                padding: 30px;
            }
            .header {
                background-color: var(--darker-bg);
                color: var(--hacker-green);
                padding: 20px;
                border: 2px solid var(--hacker-green);
                margin-bottom: 20px;
                text-shadow: 0 0 8px var(--hacker-green);
                position: relative;
                overflow: hidden;
                font-family: 'Press Start 2P', cursive;
                text-align: center;
                animation: neon-pulse 3s infinite alternate;
            }
            @keyframes neon-pulse {
                from { box-shadow: 0 0 5px var(--hacker-green), 0 0 10px var(--hacker-green); }
                to { box-shadow: 0 0 10px var(--hacker-green), 0 0 20px var(--hacker-green); }
            }
            h1 {
                margin: 0;
                font-size: 28px;
                letter-spacing: 3px;
                text-transform: uppercase;
            }
            h2 {
                color: var(--accent-blue);
                border-bottom: 2px solid var(--accent-blue);
                padding-bottom: 8px;
                margin-top: 40px;
                text-transform: uppercase;
                font-size: 22px;
                font-family: 'Press Start 2P', cursive;
                letter-spacing: 1.5px;
            }
            h3 {
                color: var(--hacker-green);
                margin-top: 25px;
                font-size: 18px;
                border-left: 3px solid var(--hacker-green);
                padding-left: 10px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                border: 1px solid var(--border-color);
            }
            th, td {
                padding: 15px;
                text-align: left;
                border: 1px solid var(--border-color);
            }
            th {
                background-color: var(--code-bg);
                color: var(--hacker-green);
                font-weight: bold;
                letter-spacing: 1px;
                text-transform: uppercase;
            }
            tr:nth-child(even) {
                background-color: rgba(0, 255, 0, 0.05);
            }
            tr:hover {
                background-color: rgba(0, 255, 0, 0.15);
            }
            .success-badge {
                display: inline-block;
                background-color: rgba(0, 255, 0, 0.2);
                color: var(--hacker-green);
                padding: 10px 20px;
                border: 2px dashed var(--hacker-green);
                font-size: 16px;
                margin: 20px 0;
                font-weight: bold;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.5);
                text-transform: uppercase;
                text-align: center;
                width: calc(100% - 40px);
            }
            .info-box {
                background-color: rgba(0, 170, 255, 0.1);
                border-left: 4px solid var(--accent-blue);
                padding: 20px;
                margin: 20px 0;
                border-right: 1px solid rgba(0, 170, 255, 0.3);
            }
            .info-box strong {
                color: var(--accent-blue);
                font-family: 'Press Start 2P', cursive;
            }
            .divider {
                border-top: 1px dashed rgba(0, 255, 0, 0.3);
                margin: 30px 0;
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
            .terminal-block {
                background-color: var(--code-bg);
                border: 1px solid var(--hacker-green);
                padding: 20px;
                margin: 20px 0;
                position: relative;
                box-shadow: inset 0 0 10px rgba(0, 255, 0, 0.2);
                animation: flicker 0.1s infinite alternate;
            }
            .terminal-block::before {
                content: "root@kali:~# ";
                position: absolute;
                top: 5px;
                left: 10px;
                color: var(--hacker-green);
                font-size: 14px;
                font-family: 'Press Start 2P', cursive;
                background-color: var(--code-bg);
                padding-right: 5px;
            }
            .terminal-block p, .terminal-block table {
                margin-top: 20px; /* Adjust for pseudo-element */
            }

            @keyframes flicker {
                0% { opacity: 1; }
                100% { opacity: 0.98; }
            }
            .footer {
                text-align: center;
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px dashed var(--border-color);
                color: var(--accent-blue);
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>RECON REPORT ACTIVE</h1>
            </div>

            <div class="info-box">
                <p><strong>TARGET DOMAIN:</strong><br>{{ report['domain'] }}</p>
                <p><strong>IP ADDRESS:</strong><br>{{ report['ip'] }}</p>
                <p><strong>SCAN DATE:</strong><br>{{ datetime.now().strftime('%Y-%m-%d %H:%M:%S') }}</p>
            </div>

            <div class="divider"></div>

            <div class="success-badge">>>> SCAN COMPLETED SUCCESSFULLY! <<<</div>

            <div class="divider"></div>

            <h2>SUB-DOMAINS ANALYSIS</h2>

            <div class="terminal-block">
                <h3>SecurityTrails Results</h3>
                {% if report['subdomains'] and not report['subdomains'].get('error') and report['subdomains'].get('data') %}
                <table>
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for subdomain in report['subdomains'].get('data', []) %}
                        <tr>
                            <td>{{ subdomain['subdomain'] }}</td>
                            <td>{{ subdomain['ip'] }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No se encontraron subdominios de SecurityTrails o hubo un error: {{ report['subdomains'].get('error', 'N/A') if report['subdomains'] else 'N/A' }}</p>
                {% endif %}
            </div>

            <div class="terminal-block">
                <h3>crt.sh Results</h3>
                {% if report['crtsh_subdomains'] %}
                <table>
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for subdomain in report['crtsh_subdomains'] %}
                        <tr>
                            <td>{{ subdomain['subdomain'] }}</td>
                            <td>{{ subdomain['ip'] }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No se encontraron subdominios estándar en crt.sh.</p>
                {% endif %}
            </div>

            <div class="terminal-block">
                <h3>Wildcard Subdomains (crt.sh)</h3>
                {% if report['crtsh_wildcards'] %}
                <table>
                    <thead>
                        <tr>
                            <th>Subdomain Wildcard</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for wildcard in report['crtsh_wildcards'] %}
                        <tr>
                            <td>{{ wildcard }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No se encontraron subdominios wildcard en crt.sh.</p>
                {% endif %}
            </div>

            <h2>DNS INFORMATION</h2>
            <div class="terminal-block">
                <table>
                    <thead>
                        <tr>
                            <th>Record Type</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>A Records</td>
                            <td>{{ report['dns_info']['A_records'] | join(", ") if report['dns_info']['A_records'] else 'N/A' }}</td>
                        </tr>
                        <tr>
                            <td>MX Records</td>
                            <td>{{ report['dns_info']['MX_records'] | join(", ") if report['dns_info']['MX_records'] else 'N/A' }}</td>
                        </tr>
                        <tr>
                            <td>NS Records</td>
                            <td>{{ report['dns_info']['NS_records'] | join(", ") if report['dns_info']['NS_records'] else 'N/A' }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            {% if report['shodan_info'] and not report['shodan_info'].get('error') %}
            <h2>SHODAN RESULTS</h2>
            <div class="terminal-block">
                <table>
                    <thead>
                        <tr>
                            <th>Field</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
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
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="terminal-block">
                <p>No se encontraron resultados de Shodan o hubo un error: {{ report['shodan_info'].get('error', 'N/A') if report['shodan_info'] else 'N/A' }}</p>
            </div>
            {% endif %}

            {% if report['netlas_info'] and not report['netlas_info'].get('error') and report['netlas_info']['items'] %}
            <h2>NETLAS RESULTS</h2>
            <div class="terminal-block">
                <table>
                    <thead>
                        <tr>
                            <th>Field</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for key, value in report['netlas_info']['items'][0].items() %}
                            {% if key not in ['_shards', 'timed_out', 'took'] and value %}
                            <tr>
                                <td>{{ key }}</td>
                                <td>
                                    {% if value is mapping %}
                                        {% for k, v in value.items() %}
                                            <strong>{{ k }}:</strong> {{ v }}<br>
                                        {% endfor %}
                                    {% elif value is iterable and value is not string %}
                                        {{ value|join(", ") }}
                                    {% else %}
                                        {{ value }}
                                    {% endif %}
                                </td>
                            </tr>
                            {% endif %}
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="terminal-block">
                <p>No se encontraron resultados de Netlas o hubo un error: {{ report['netlas_info'].get('error', 'N/A') if report['netlas_info'] else 'N/A' }}</p>
            </div>
            {% endif %}

            {% if report['hunterhow_info'] and not report['hunterhow_info'].get('error') %}
            <h2>HUNTER.HOW RESULTS</h2>
            <div class="terminal-block">
                {% if report['hunterhow_info']['results'] %}
                    <table>
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>IP</th>
                                <th>Port</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in report['hunterhow_info']['results'] %}
                            <tr>
                                <td>{{ item['domain'] }}</td>
                                <td>{{ item['ip'] }}</td>
                                <td>{{ item['port'] }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    
                    <div style="margin-top: 20px; color: var(--accent-blue); font-size: 0.9em;">
                        <p><strong>API Usage:</strong> 
                        {{ report['hunterhow_info']['limits']['per_day_search_count'] }}/{{ report['hunterhow_info']['limits']['per_day_search_limit'] }} searches today |
                        {{ report['hunterhow_info']['limits']['per_day_api_pull_count'] }}/{{ report['hunterhow_info']['limits']['per_day_api_pull_limit'] }} API pulls today</p>
                    </div>
                {% else %}
                    <p>No se encontraron resultados en Hunter.how.</p>
                {% endif %}
            </div>
            {% else %}
            <div class="terminal-block">
                <p>No se encontraron resultados de Hunter.how o hubo un error: {{ report['hunterhow_info'].get('error', 'N/A') if report['hunterhow_info'] else 'N/A' }}</p>
            </div>
            {% endif %}

            {% if report['google_dorks'] %}
            <h2>GOOGLE DORKS RESULTS</h2>
            <div class="terminal-block">
                {% for dork, results in report['google_dorks'].items() %}
                    <h3>{{ dork }}</h3>
                    {% if results is iterable and results is not string and results %}
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for result in results %}
                            <tr>
                                <td><a href="{{ result }}" target="_blank">{{ result }}</a></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    {% else %}
                    <p>No se encontraron resultados para este dork o hubo un error.</p>
                    {% endif %}
                {% endfor %}
            </div>
            {% endif %}

            {% if report['leaks'] %}
            <h2>DATA LEAKS</h2>
            <div class="terminal-block">
                {% if report['leaks'] %}
                <table>
                    <thead>
                        <tr>
                            <th>Record</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for leak in report['leaks'] %}
                        <tr>
                            <td>{{ leak }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <p>No se encontraron fugas de información.</p>
                {% endif %}
            </div>
            {% endif %}

            <div class="divider"></div>
            <div class="footer">
                [ RECON TOOL BY CREADPAG | {{ datetime.now().strftime('%Y') }} ]
            </div>
        </div>
    </body>
    </html>
    """
    
    template = Template(html_template)
    html_content = template.render(report=report, datetime=datetime)

    report_filename = os.path.join(output_folder, f"recon_report_{report['domain']}.html")
    with open(report_filename, 'w', encoding='utf-8') as file:
        file.write(html_content)
    return report_filename

# <--- NUEVA FUNCIÓN analyze_domain AQUÍ --- >
def analyze_domain(domain, api_keys):
    report = {
        "domain": domain,
        "ip": None,
        "subdomains": {},
        "crtsh_subdomains": [],
        "crtsh_wildcards": [],
        "dns_info": {},
        "shodan_info": {},
        "netlas_info": {},
        "hunterhow_info": {},
        "google_dorks": {},
        "leaks": []
    }

    # 1. Obtener IP
    report["ip"] = get_ip_from_domain(domain)

    # 2. Obtener subdominios de crt.sh
    report["crtsh_subdomains"], report["crtsh_wildcards"] = get_crtsh_subdomains(domain)

    # 3. Obtener registros DNS
    report["dns_info"] = get_dns_records(domain)

    # 4. Obtener subdominios de SecurityTrails
    report["subdomains"] = get_securitytrails_subdomains(api_keys.get("securitytrails"), domain)

    # 5. Obtener información de Shodan
    if report["ip"] and "Error" not in report["ip"]: # Solo si la IP se obtuvo correctamente
        report["shodan_info"] = get_shodan_info(api_keys.get("shodan"), report["ip"])
    else:
        console.print("[bold yellow]Saltando Shodan: IP no disponible o error al obtenerla.[/bold yellow]")
        report["shodan_info"] = {"error": "IP no disponible para Shodan"}

    # 6. Obtener información de Netlas
    report["netlas_info"] = get_netlas_info(api_keys.get("netlas"), domain)

    # 7. Obtener información de Hunter.how
    report["hunterhow_info"] = query_hunterhow(domain, api_keys.get("hunterhow"))

    # 8. Google Dorks (con API o sin ella)
    if api_keys.get("google_api_key") and api_keys.get("google_cse_id"):
        report["google_dorks"] = get_google_dorks_api(domain, api_keys["google_api_key"], api_keys["google_cse_id"])
    else:
        console.print("[bold yellow]Google API Keys no configuradas. Intentando Google Dorks via scraping (puede ser inestable).[/bold yellow]")
        report["google_dorks"] = get_google_dorks_scraper(domain)
    
    # Descargar archivos encontrados con Google Dorks
    google_dork_download_folder = os.path.join(os.getcwd(), domain.replace('.', '_'), "google_dork_downloads")
    download_files_from_dorks(report["google_dorks"], google_dork_download_folder)

    # 9. Buscar fugas de información
    report["leaks"] = find_leaks_proxynova(domain)

    return report
# <--- FIN DE LA NUEVA FUNCIÓN analyze_domain --- >

# Función principal
def main():
    print_hacker_banner()
    args = parse_args()

    # Define tus API Keys aquí. Si no tienes una, déjala como cadena vacía "".
    api_keys = {
        "shodan": "", # Tu API Key de Shodan aquí
        "securitytrails": "", # Tu API Key de SecurityTrails aquí
        "google_api_key": "YOUR_GOOGLE_API_KEY", # <--- ¡PON TU CLAVE AQUÍ!
        "google_cse_id": "YOUR_GOOGLE_CSE_ID", # <--- ¡PON TU ID DE CUSTOM SEARCH ENGINE AQUÍ!
        "netlas": "", # Tu API Key de Netlas aquí
        "hunterhow": "" # Tu API Key de Hunter.how aquí
    }
    
    domains_to_analyze = []
    if args.domain:
        domains_to_analyze.append(args.domain)
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                for line in f:
                    domain = line.strip()
                    if domain: # Asegurarse de que la línea no esté vacía
                        domains_to_analyze.append(domain)
        except FileNotFoundError:
            console.print(f"[bold red]Error: El archivo de lista '{args.list}' no fue encontrado.[/bold red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Error al leer el archivo de lista:[/bold red] {e}")
            sys.exit(1)

    if not domains_to_analyze:
        console.print("[bold red]No se encontraron dominios para analizar. Asegúrate de que el archivo de lista no esté vacío.[/bold red]")
        sys.exit(1)

    for domain in domains_to_analyze:
        console.print(Panel(f"[bold blue]Iniciando análisis para el dominio:[/bold blue] [bold yellow]{domain}[/bold yellow]", border_style="green", expand=False))
        
        output_folder = os.path.join(os.getcwd(), domain.replace('.', '_'))
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)
            console.print(f"[bold green]Carpeta de salida creada:[/bold green] {output_folder}")
        else:
            console.print(f"[bold yellow]Carpeta de salida ya existe:[/bold yellow] {output_folder}")

        report = analyze_domain(domain, api_keys)
        
        # Generar y guardar el informe HTML en la nueva carpeta
        html_report_filename = generate_html_report(report, output_folder)
        console.print(f"[bold green]Informe HTML generado y guardado como '{html_report_filename}'[/bold green]")

        # Generar y guardar el informe Excel en la nueva carpeta
        excel_report_filename = generate_excel_report(report, output_folder)
        if excel_report_filename:
            console.print(f"[bold green]Informe Excel generado y guardado como '{excel_report_filename}'[/bold green]")
        
        console.print(Panel(f"[bold blue]Análisis completado para el dominio:[/bold blue] [bold yellow]{domain}[/bold yellow]\n", border_style="green", expand=False))
        console.print("\n" + "="*80 + "\n") # Separador visual entre dominios

if __name__ == "__main__":
    main()
