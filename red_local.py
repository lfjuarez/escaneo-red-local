"""Motor compartido de escanear-red.py y vigilar-red.py (Mac y Linux).

Releva la red local con las herramientas que trae el sistema y devuelve una lista de equipos.
Nada está fijo: la interfaz, la red, el router y los tipos de servicio se descubren en el momento.

Fuentes de cada dato:
  IP y MAC ............ tabla ARP (arp -an en Mac, ip neigh en Linux)
  Fabricante .......... los primeros 3 bytes de la MAC, en la base de la IEEE (fabricantes-mac.txt)
  MAC privada ......... el bit «administrada localmente» de la MAC
  Latencia y sistema .. dos pings: el tiempo de respuesta y el TTL (64, 128 o 255)
  Nombre .............. lo que el equipo anuncia, la consulta inversa por mDNS y el DNS del router
  Servicios, modelo ... los anuncios mDNS/DNS-SD (dns-sd en Mac, avahi-browse en Linux)
  Tipo de equipo ...... se deduce de los servicios que anuncia y de su modelo
"""
from __future__ import annotations

import csv
import ipaddress
import os
import platform
import re
import resource
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

ES_MAC = platform.system() == "Darwin"
CARPETA = Path(__file__).resolve().parent
BASE_FABRICANTES = CARPETA / "fabricantes-mac.txt"   # copia de https://www.wireshark.org/download/automated/data/manuf
INVENTARIO = CARPETA / "inventario-activos.csv"
REGISTRO = CARPETA / "alertas-red.log"
ESCUCHA = 4          # segundos que se escucha cada consulta de anuncios

# Cada comando en paralelo abre varios archivos (sus canales de entrada y salida). La terminal tiene un límite
# (en macOS suele ser 256), así que la cantidad de comandos simultáneos se calcula a partir de ese límite.
try:
    _limite_archivos = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
except (ValueError, OSError):
    _limite_archivos = 256
MAX_SIMULTANEOS = max(8, min(64, (_limite_archivos - 40) // 4))
MAX_BARRIDO = 1024   # tope de direcciones para el barrido activo

COLUMNAS_INVENTARIO = ["MAC", "IP", "Nombre", "Fabricante", "Tipo", "Modelo", "Sistema", "Servicios",
                       "Primera vez", "Última vez", "Autorizado", "Responsable"]

# Tipo de servicio anunciado → (etiqueta para mostrar, clase de equipo que sugiere)
SERVICIOS = {
    "_airplay._tcp": ("AirPlay", "pantalla"), "_raop._tcp": ("AirPlay audio", "pantalla"),
    "_googlecast._tcp": ("Chromecast", "tv"), "_androidtvremote2._tcp": ("Android TV", "tv"),
    "_amzn-wplay._tcp": ("Amazon", "tv"), "_spotify-connect._tcp": ("Spotify Connect", "audio"),
    "_sonos._tcp": ("Sonos", "audio"),
    "_ipp._tcp": ("Impresión", "impresora"), "_ipps._tcp": ("Impresión segura", "impresora"),
    "_printer._tcp": ("Impresión LPR", "impresora"), "_pdl-datastream._tcp": ("Impresión directa", "impresora"),
    "_scanner._tcp": ("Escáner", "impresora"), "_uscan._tcp": ("Escáner", "impresora"),
    "_hap._tcp": ("HomeKit", "domotica"), "_homekit._tcp": ("HomeKit", "domotica"),
    "_matter._tcp": ("Matter", "domotica"), "_matterc._udp": ("Matter", "domotica"), "_mqtt._tcp": ("MQTT", "domotica"),
    "_apple-mobdev2._tcp": ("Sincronización iPhone/iPad", "movil_apple"),
    "_companion-link._tcp": ("Enlace Apple", "apple"), "_sleep-proxy._udp": ("Reposo Apple", "apple"),
    "_ssh._tcp": ("SSH", "compu"), "_sftp-ssh._tcp": ("SFTP", "compu"), "_smb._tcp": ("Archivos SMB", "compu"),
    "_afpovertcp._tcp": ("Archivos AFP", "compu"), "_nfs._tcp": ("Archivos NFS", "compu"),
    "_rfb._tcp": ("Pantalla compartida", "compu"), "_workstation._tcp": ("Estación de trabajo", "compu"),
    "_http._tcp": ("Web", ""), "_https._tcp": ("Web segura", ""),
}
# Prefijo del identificador de modelo que anuncian los equipos de Apple → tipo de equipo
MODELOS_APPLE = (("Mac", "Computadora Apple"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                 ("AppleTV", "Apple TV"), ("AudioAccessory", "HomePod"))
SISTEMA_POR_TTL = {64: "Linux, Android o Apple", 128: "Windows", 255: "Equipo de red"}


# ───────────────────────── utilidades ─────────────────────────
def correr(cmd, segundos=15, cortar=False):
    """Corre un comando y devuelve su salida. Con cortar=True lo corta a los `segundos` (dns-sd no termina solo)."""
    if not shutil.which(cmd[0]):
        return ""
    try:
        if cortar:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True)
            time.sleep(segundos)
            p.terminate()
            return p.communicate()[0]
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                              text=True, timeout=segundos).stdout
    except subprocess.TimeoutExpired:
        return ""
    except OSError:          # sin recursos para abrir otro proceso: se pierde este dato, no el escaneo
        return ""


def en_paralelo(funcion, elementos, hilos=None):
    elementos = list(elementos)
    if not elementos:
        return []
    with ThreadPoolExecutor(min(hilos or MAX_SIMULTANEOS, MAX_SIMULTANEOS, len(elementos))) as ex:
        return list(ex.map(funcion, elementos))


def normalizar_mac(mac):
    return ":".join(x.zfill(2) for x in mac.lower().replace("-", ":").split(":"))


def es_ip_de_equipo(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and not (a.is_multicast or a.is_loopback or a.is_link_local or ip.endswith(".255"))


def ahora():
    return datetime.now().strftime("%d/%m/%Y %H:%M")


# ───────────────────────── datos de esta computadora y de la red ─────────────────────────
@dataclass
class Red:
    interfaz: str = ""
    ip: str = ""
    mac: str = ""
    red: ipaddress.IPv4Network | None = None
    router: str = ""
    dns: list = field(default_factory=list)
    wifi: str = ""
    equipo: str = ""     # marca y modelo de esta computadora
    sistema: str = ""    # sistema operativo de esta computadora
    proxy: int = 0       # direcciones por las que responde una misma MAC (proxy ARP)


def leer_red():
    r = Red()
    if ES_MAC:
        ruta = correr(["route", "-n", "get", "default"])
        r.router = _buscar(r"gateway: ([\d.]+)", ruta)
        r.interfaz = _buscar(r"interface: (\S+)", ruta)
        cfg = correr(["ifconfig", r.interfaz]) if r.interfaz else ""
        r.ip = _buscar(r"inet ([\d.]+)", cfg)
        mac = _buscar(r"ether ([0-9a-f:]+)", cfg)
        r.mac = normalizar_mac(mac) if mac else ""
        mascara = _buscar(r"netmask (0x[0-9a-f]+)", cfg)
        prefijo = bin(int(mascara, 16)).count("1") if mascara else 24
        r.dns = list(dict.fromkeys(re.findall(r"nameserver\[\d+\] : (\S+)", correr(["scutil", "--dns"]))))[:3]
        perfil = correr(["system_profiler", "SPHardwareDataType", "SPAirPortDataType"], 30)
        r.equipo = " ".join(x for x in (_buscar(r"Model Name: (.+)", perfil),
                                        "(" + _buscar(r"Model Identifier: (.+)", perfil) + ")") if x.strip("()"))
        r.sistema = "macOS " + platform.mac_ver()[0]
        actual = perfil.split("Current Network Information:")[1][:700] if "Current Network Information:" in perfil else ""
        r.wifi = " · ".join(x for x in (_buscar(r"Security: (.+)", actual),
                                        "canal " + _buscar(r"Channel: (.+)", actual) if "Channel:" in actual else "",
                                        _buscar(r"PHY Mode: (.+)", actual)) if x)
    else:
        ruta = correr(["ip", "-4", "route", "get", "1.1.1.1"])
        r.router = _buscar(r"via ([\d.]+)", ruta)
        r.interfaz = _buscar(r"dev (\S+)", ruta)
        r.ip = _buscar(r"src ([\d.]+)", ruta)
        prefijo = int(_buscar(r"inet [\d.]+/(\d+)", correr(["ip", "-4", "-o", "addr", "show", "dev", r.interfaz])) or 24)
        archivo_mac = Path("/sys/class/net") / r.interfaz / "address"
        r.mac = normalizar_mac(archivo_mac.read_text().strip()) if archivo_mac.exists() else ""
        resolv = Path("/etc/resolv.conf")
        r.dns = re.findall(r"^nameserver\s+(\S+)", resolv.read_text(), re.M)[:3] if resolv.exists() else []
        dmi = Path("/sys/class/dmi/id")
        r.equipo = " ".join((dmi / x).read_text().strip() for x in ("sys_vendor", "product_name") if (dmi / x).exists())
        r.sistema = correr(["sh", "-c", ". /etc/os-release && echo $PRETTY_NAME"]).strip() or "Linux"
        wifi = [l for l in correr(["nmcli", "-t", "-f", "ACTIVE,SECURITY,CHAN", "dev", "wifi"]).splitlines() if l.startswith("yes:")]
        r.wifi = " · canal ".join(wifi[0].split(":")[1:3]) if wifi else ""
    if r.ip:
        r.red = ipaddress.ip_network(f"{r.ip}/{prefijo}", strict=False)
    return r


def _buscar(patron, texto):
    m = re.search(patron, texto)
    return m.group(1).strip() if m else ""


def trafico_propio(interfaz):
    """Bytes recibidos y enviados por esta computadora desde que se encendió."""
    if ES_MAC:
        for l in correr(["netstat", "-ibn", "-I", interfaz]).splitlines():
            c = l.split()
            if len(c) >= 10 and c[2].startswith("<Link"):
                return int(c[6]), int(c[9])
    else:
        base = Path("/sys/class/net") / interfaz / "statistics"
        if base.exists():
            return int((base / "rx_bytes").read_text()), int((base / "tx_bytes").read_text())
    return None


def bytes_legibles(n):
    for unidad in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unidad}"
        n /= 1024
    return f"{n:.0f} PB"


# ───────────────────────── descubrimiento ─────────────────────────
def leer_vecinos():
    """La tabla ARP: {ip: mac} de los equipos con los que esta computadora habló hace poco."""
    vecinos = {}
    if ES_MAC:
        for l in correr(["arp", "-an"]).splitlines():
            m = re.search(r"\(([\d.]+)\) at ([0-9a-f:]+) on ", l)
            if m and "permanent" not in l and es_ip_de_equipo(m.group(1)):
                vecinos[m.group(1)] = normalizar_mac(m.group(2))
    else:
        for l in correr(["ip", "-4", "neigh"]).splitlines():
            m = re.match(r"([\d.]+) dev \S+ lladdr ([0-9a-f:]+) (\w+)", l)
            if m and m.group(3) not in ("FAILED", "INCOMPLETE") and es_ip_de_equipo(m.group(1)):
                vecinos[m.group(1)] = normalizar_mac(m.group(2))
    return vecinos


def quitar_proxy(vecinos, router):
    """Si una misma MAC responde por muchas IP (proxy ARP, típico de redes en la nube), deja una sola. Devuelve cuántas quitó."""
    por_mac = defaultdict(list)
    for ip, mac in vecinos.items():
        if mac:
            por_mac[mac].append(ip)
    quitadas = 0
    for ips in por_mac.values():
        if len(ips) >= 4:
            conservar = router if router in ips else min(ips, key=ipaddress.ip_address)
            for ip in ips:
                if ip != conservar:
                    del vecinos[ip]
                    quitadas += 1
    return quitadas


def direcciones_a_barrer(red):
    """Las direcciones de la red local. Si la red es muy grande, solo las 254 vecinas a esta computadora."""
    if not red.red:
        return []
    zona = red.red if red.red.num_addresses <= MAX_BARRIDO else ipaddress.ip_network(f"{red.ip}/24", strict=False)
    return [str(h) for h in zona.hosts() if str(h) != red.ip]


def barrer(red):
    """Descubrimiento activo: un ping a cada dirección para que los equipos encendidos queden en la tabla ARP."""
    espera = ["-W", "1000"] if ES_MAC else ["-W", "1"]
    en_paralelo(lambda ip: correr(["ping", "-c", "1", *espera, ip], 3), direcciones_a_barrer(red))


def sondear(ip):
    """Dos pings: devuelve (responde, latencia en ms, TTL). El primero suele despertar al equipo; se toma el mejor."""
    espera = ["-W", "1000"] if ES_MAC else ["-W", "1"]
    respuestas = re.findall(r"ttl=(\d+) time=([\d.]+)", correr(["ping", "-c", "2", "-i", "0.3", *espera, ip], 5))
    if not respuestas:
        return ip, (False, None, None)
    return ip, (True, min(float(t) for _, t in respuestas), int(respuestas[0][0]))


def nombre_inverso(ip, router):
    """El nombre de una IP: primero por mDNS (lo dice el propio equipo) y después por el DNS del router."""
    if ES_MAC:
        consultas = [["dig", "+short", "+time=2", "+tries=1", "-x", ip, "@224.0.0.251", "-p", "5353"]]
        if router:
            consultas.append(["dig", "+short", "+time=2", "+tries=1", "-x", ip, "@" + router])
    else:
        consultas = [["avahi-resolve-address", ip], ["getent", "hosts", ip]]
    for consulta in consultas:
        for linea in correr(consulta, 5).splitlines():
            campos = linea.split()
            if campos and not linea.startswith(";"):
                return ip, campos[-1].rstrip(".")
    return ip, ""


@dataclass
class Anuncio:
    ip: str
    host: str
    tipo: str        # por ejemplo «_airplay._tcp»
    instancia: str   # el nombre con el que el equipo se presenta
    puerto: str
    datos: dict      # fabricante, modelo y nombre que vienen en la ficha


CLAVES_FICHA = "model|md|manufacturer|fn|ty|usb_MDL|usb_MFG|product"


def leer_anuncios():
    """Todo lo que los equipos anuncian por mDNS/DNS-SD, sea cual sea el tipo de servicio."""
    return _anuncios_mac() if ES_MAC else _anuncios_linux()


def _anuncios_mac():
    def quitar_escapes(v):
        v = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), v)
        return re.sub(r"\\(.)", r"\1", v).strip("()")

    tipos = {f"{m.group(2)}.{m.group(1)}" for m in re.finditer(
        r"\sAdd\s+\d+\s+\d+\s+\S+\s+(_tcp|_udp)\.\S*\s+(_[\w-]+)",
        correr(["dns-sd", "-B", "_services._dns-sd._udp", "local."], ESCUCHA, cortar=True))}

    def instancias(tipo):
        salida = correr(["dns-sd", "-B", tipo, "local."], ESCUCHA, cortar=True)
        return [(tipo, m.group(1).strip()) for m in re.finditer(r"\sAdd\s+\d+\s+\d+\s+\S+\s+\S+\s+(.+)$", salida, re.M)]

    def ficha(par):
        tipo, instancia = par
        for _ in range(2):                                    # un equipo dormido puede no contestar la primera vez
            salida = correr(["dns-sd", "-L", instancia, tipo, "local."], ESCUCHA, cortar=True)
            m = re.search(r"can be reached at (\S+?)\.?:(\d+)", salida)
            if m:
                break
        datos = {k: quitar_escapes(v) for k, v in re.findall(r"\b(" + CLAVES_FICHA + r")=((?:\\.|[^ \n])+)", salida)}
        return tipo, instancia, (m.group(1) if m else ""), (m.group(2) if m else ""), datos

    def ip_de(host):
        for _ in range(2):
            m = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b\s+\d+\s*$", correr(["dns-sd", "-G", "v4", host], ESCUCHA, cortar=True), re.M)
            if m:
                return host, m.group(1)
        return host, ""

    fichas = en_paralelo(ficha, {par for lista in en_paralelo(instancias, tipos) for par in lista})
    ips = dict(en_paralelo(ip_de, {f[2] for f in fichas if f[2]}))
    return [Anuncio(ips.get(host, ""), host, tipo, instancia, puerto, datos) for tipo, instancia, host, puerto, datos in fichas]


def _anuncios_linux():
    anuncios = []
    for l in correr(["avahi-browse", "-a", "-r", "-t", "-p", "-k"], 25).splitlines():
        c = l.split(";")
        if c[0] == "=" and len(c) >= 10 and c[2] == "IPv4":
            datos = dict(re.findall(r'"(' + CLAVES_FICHA + r')=([^"]*)"', c[9]))
            instancia = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), c[3])
            anuncios.append(Anuncio(c[7], c[6], c[4], instancia, c[8], datos))
    return anuncios


# ───────────────────────── equipos ─────────────────────────
@dataclass
class Equipo:
    ip: str
    mac: str = ""
    nombre: str = ""
    marca: str = ""
    modelo: str = ""
    tipo: str = ""
    responde: bool = False
    latencia: float | None = None
    ttl: int | None = None
    sistema: str = ""
    servicios: dict = field(default_factory=dict)   # etiqueta → puerto
    clases: set = field(default_factory=set)        # clases de equipo que sugieren sus servicios

    @property
    def mac_privada(self):
        """El bit «administrada localmente»: la MAC no es la de fábrica (celulares y compus que la ocultan)."""
        return bool(self.mac) and bool(int(self.mac[:2], 16) & 0b10)

    @property
    def clave(self):
        return self.mac or "ip:" + self.ip


def cargar_fabricantes():
    tabla = {}
    if BASE_FABRICANTES.exists():
        for l in BASE_FABRICANTES.read_text(errors="ignore").splitlines():
            partes = l.split("\t")
            if len(partes) > 1 and len(partes[0].strip()) == 8:      # bloques de 3 bytes: AA:BB:CC
                tabla[partes[0].strip().lower()] = partes[-1].strip()
    return tabla


def fabricante_de(equipo, tabla):
    if not equipo.mac:
        return ""
    if equipo.mac_privada:
        return "privada"
    nombre = tabla.get(equipo.mac[:8], "desconocido")
    corto = re.sub(r"[,\s]+(Co\.?|Ltd\.?|Inc\.?|Corp\.?|Corporation|Technologies|Technology|Electronics|International)\b.*$", "", nombre)
    return corto.strip(" ,") or nombre


def _nombre_presentable(instancia):
    """Descarta identificadores que no son nombres: códigos, direcciones MAC y nombres de aplicación."""
    nombre = re.sub(r"^[0-9A-Fa-f]{12}@", "", instancia).strip()
    if re.fullmatch(r"[0-9a-fA-F-]{20,}", nombre) or re.match(r"[0-9a-fA-F:]{17}@", nombre) or re.fullmatch(r"[a-z]{2,}(\.[\w-]+){2,}", nombre):
        return ""
    return nombre


def _tipo_de(equipo, red):
    if equipo.ip == red.ip:
        return "Esta computadora"
    if equipo.ip == red.router:
        return "Router"
    for prefijo, tipo in MODELOS_APPLE:
        if equipo.modelo.startswith(prefijo):
            return tipo
    for clase, tipo in (("impresora", "Impresora"), ("movil_apple", "iPhone o iPad"), ("tv", "TV o reproductor"),
                        ("compu", "Computadora"), ("pantalla", "TV o pantalla"), ("audio", "Parlante"),
                        ("domotica", "Domótica"), ("apple", "Equipo Apple")):
        if clase in equipo.clases:
            return tipo
    return "Celular o compu" if equipo.mac_privada else ""


def relevar(barrido=False, anuncios=True, avisar=lambda texto: None):
    """Releva la red y devuelve (red, equipos ordenados por IP)."""
    avisar("leyendo los datos de esta computadora y de la red")
    red = leer_red()
    if barrido:
        avisar(f"barrido activo: un ping a {len(direcciones_a_barrer(red))} direcciones")
        barrer(red)
    vecinos = leer_vecinos()
    red.proxy = quitar_proxy(vecinos, red.router)
    avisar(f"midiendo latencia y TTL de {len(vecinos)} equipos")
    sondeos = dict(en_paralelo(sondear, vecinos))
    lista = []
    if anuncios:
        avisar("escuchando lo que los equipos anuncian")
        lista = [a for a in leer_anuncios() if a.ip and es_ip_de_equipo(a.ip)]
        faltan = {a.ip for a in lista} - set(vecinos) - {red.ip}
        sondeos.update(en_paralelo(sondear, faltan))          # el ping los deja en la tabla ARP
        vecinos = {**dict.fromkeys(faltan, ""), **vecinos, **{ip: mac for ip, mac in leer_vecinos().items() if ip in vecinos or ip in faltan}}
    avisar("preguntando el nombre de cada equipo")
    nombres = dict(en_paralelo(lambda ip: nombre_inverso(ip, red.router), vecinos))

    equipos = {ip: Equipo(ip=ip, mac=mac) for ip, mac in vecinos.items()}
    if red.ip:
        equipos[red.ip] = Equipo(ip=red.ip, mac=red.mac, responde=True, modelo=red.equipo, sistema=red.sistema)
    presentaciones = {ip: Counter() for ip in equipos}
    for a in lista:
        e = equipos.get(a.ip)
        if not e:
            continue
        etiqueta, clase = SERVICIOS.get(a.tipo, (a.tipo.split(".")[0].lstrip("_"), ""))
        e.servicios[etiqueta] = a.puerto
        e.clases.add(clase)
        presentable = _nombre_presentable(a.datos.get("fn") or a.instancia)
        if presentable:
            presentaciones[a.ip][presentable] += 1
        if a.ip != red.ip:
            e.marca = e.marca or a.datos.get("manufacturer") or a.datos.get("usb_MFG") or ""
            modelo = a.datos.get("model") or a.datos.get("md") or a.datos.get("usb_MDL") or a.datos.get("ty") or a.datos.get("product") or ""
            e.modelo = e.modelo or (modelo if re.search(r"[A-Za-z]", modelo) else "")
        nombres[a.ip] = nombres.get(a.ip) or a.host

    for ip, e in equipos.items():
        if ip != red.ip:
            e.responde, e.latencia, e.ttl = sondeos.get(ip, (False, None, None))
            e.sistema = SISTEMA_POR_TTL.get(e.ttl, f"poco común (TTL {e.ttl})") if e.ttl else ""
        en_red = re.sub(r"\.local$", "", nombres.get(ip, ""))
        anunciado = presentaciones[ip].most_common(1)[0][0] if presentaciones[ip] else ""
        e.nombre = anunciado or ("" if en_red == "localhost" else en_red) or (socket.gethostname().split(".")[0] if ip == red.ip else "")
        e.tipo = _tipo_de(e, red)
    return red, sorted(equipos.values(), key=lambda e: ipaddress.ip_address(e.ip))


# ───────────────────────── presentación ─────────────────────────
COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
ROJO, AMARILLO, VERDE, GRIS, NEGRITA = "31", "33", "32", "90", "1"


def pintar(texto, codigo):
    return f"\033[{codigo}m{texto}\033[0m" if COLOR else texto


def mostrar_mac(mac, completa):
    return mac if completa or not mac else mac[:8] + ":xx:xx:xx"


def fila_de(e, fabricantes, mac_completa):
    """Un equipo como fila de tabla. Cada dato aparece una sola vez."""
    marca = "" if e.marca and fabricante_de(e, fabricantes).lower().startswith(e.marca.split()[0].lower()) else e.marca
    modelo = " ".join(x for x in (marca, e.modelo) if x)
    return {
        "IP": e.ip,
        "MAC": mostrar_mac(e.mac, mac_completa),
        "Fabricante": fabricante_de(e, fabricantes),
        "Nombre": e.nombre if len(e.nombre) <= 28 else e.nombre[:27] + "…",
        "Tipo": e.tipo,
        "Modelo": "" if modelo == e.nombre else modelo,
        "Sistema": e.sistema,
        "Latencia": "" if e.tipo == "Esta computadora" else (f"{e.latencia:.0f} ms" if e.responde else "no responde"),
        "Servicios": ", ".join(f"{s} :{p}" for s, p in sorted(e.servicios.items())),
    }


def imprimir_tabla(filas, color=None):
    """Imprime una lista de diccionarios como tabla. Las columnas vacías no se muestran."""
    if not filas:
        return
    columnas = [c for c in filas[0] if any(f[c] for f in filas)]
    anchos = {c: max(len(c), *(len(str(f[c])) for f in filas)) for c in columnas}
    print(pintar("  ".join(c.ljust(anchos[c]) for c in columnas).rstrip(), NEGRITA))
    print(pintar("  ".join("─" * anchos[c] for c in columnas), GRIS))
    for f in filas:
        linea = "  ".join(str(f[c]).ljust(anchos[c]) for c in columnas).rstrip()
        print(pintar(linea, color(f)) if color and color(f) else linea)


def encabezado(titulo, red, metodo):
    print(pintar(f"\n{titulo} · {ahora()}", NEGRITA))
    datos = [("Esta computadora", " · ".join(x for x in (red.equipo, red.sistema, red.ip, red.interfaz) if x)),
             ("Red", f"{red.red} · {red.red.num_addresses - 2} direcciones posibles" if red.red else "sin conexión"),
             ("Router", red.router), ("DNS en uso", ", ".join(red.dns)), ("Wi-Fi", red.wifi), ("Método", metodo),
             ("Aviso", f"una misma MAC responde por {red.proxy + 1} direcciones (proxy ARP): se cuenta como un solo equipo" if red.proxy else "")]
    trafico = trafico_propio(red.interfaz) if red.interfaz else None
    if trafico:
        datos.append(("Tráfico propio", f"recibido {bytes_legibles(trafico[0])} · enviado {bytes_legibles(trafico[1])} desde el encendido"))
    for etiqueta, valor in datos:
        if valor:
            print(f"  {pintar(etiqueta.ljust(17), GRIS)} {valor}")
    print()


def metodo_usado(barrido, red):
    if barrido:
        return f"activo: barrido de {len(direcciones_a_barrer(red))} direcciones + tabla ARP + anuncios"
    return "pasivo: tabla ARP + anuncios de los equipos (con --barrido se saluda a toda la red)"


def progreso(texto):
    if sys.stderr.isatty():
        print(f"\r\033[K  … {texto}", end="", file=sys.stderr, flush=True)


def fin_progreso():
    if sys.stderr.isatty():
        print("\r\033[K", end="", file=sys.stderr, flush=True)


# ───────────────────────── inventario de activos ─────────────────────────
def leer_inventario():
    """El inventario guardado: {clave: fila}. La clave es la MAC (o «ip:…» si no hay MAC)."""
    if not INVENTARIO.exists():
        return {}
    with INVENTARIO.open(newline="", encoding="utf-8-sig") as archivo:
        return {(f["MAC"] or "ip:" + f["IP"]): f for f in csv.DictReader(archivo)}


def guardar_inventario(inventario):
    filas = sorted(inventario.values(), key=lambda f: ipaddress.ip_address(f["IP"]) if es_ip_de_equipo(f["IP"]) else ipaddress.ip_address("0.0.0.0"))
    with INVENTARIO.open("w", newline="", encoding="utf-8-sig") as archivo:
        escritor = csv.DictWriter(archivo, fieldnames=COLUMNAS_INVENTARIO)
        escritor.writeheader()
        escritor.writerows(filas)


def autorizado(fila):
    return fila.get("Autorizado", "").strip().lower() in ("sí", "si")


def servicios_de(fila):
    return {s.strip() for s in fila.get("Servicios", "").split(",") if s.strip()}


def registrar(inventario, equipos, fabricantes):
    """Suma al inventario los equipos relevados, sin tocar lo que cargó una persona. Devuelve las claves nuevas."""
    nuevas = []
    for e in equipos:
        fila = fila_de(e, fabricantes, True)
        anterior = inventario.get(e.clave)
        if not anterior:
            nuevas.append(e.clave)
            anterior = {"Primera vez": ahora(), "Autorizado": "sí" if e.tipo == "Esta computadora" else "pendiente"}
        inventario[e.clave] = {
            "MAC": e.mac, "IP": e.ip,
            "Nombre": e.nombre or anterior.get("Nombre", ""),
            "Fabricante": fila["Fabricante"],
            # «Celular o compu» sale solo de la MAC privada: no pisa un tipo mejor que ya se conocía.
            "Tipo": anterior.get("Tipo", "") if e.tipo in ("", "Celular o compu") and anterior.get("Tipo") else e.tipo,
            "Modelo": fila["Modelo"] or anterior.get("Modelo", ""),
            "Sistema": e.sistema or anterior.get("Sistema", ""),
            "Servicios": ", ".join(sorted(servicios_de(anterior) | set(e.servicios))),
            "Primera vez": anterior["Primera vez"], "Última vez": ahora(),
            "Autorizado": anterior["Autorizado"], "Responsable": anterior.get("Responsable", ""),
        }
    return nuevas
