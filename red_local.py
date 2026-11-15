"""
red_local.py — el «motor» que usan escanear-red.py y vigilar-red.py (Mac y Linux).
====================================================================================

Este archivo no se ejecuta solo: lo importan los otros dos programas. Acá está todo el trabajo de
averiguar qué hay en la red. Los otros dos programas solo deciden qué mostrar.

La idea es la misma que se hace a mano en la terminal, comando por comando, pero automatizada:

    1. ¿Dónde estoy?            → mi IP, mi red, mi router, mi DNS            (leer_red)
    2. ¿Con quién hablé?        → la tabla ARP: IP y MAC de los vecinos        (leer_vecinos)
    3. (Opcional) ¿Quién más?   → un ping a cada dirección de la red           (barrer)
    4. ¿Responde? ¿Qué sistema? → dos pings: latencia y TTL                    (sondear)
    5. ¿Qué anuncia?            → los servicios que cada equipo publica (mDNS) (leer_anuncios)
    6. ¿Cómo se llama?          → la consulta inversa de nombre                (nombre_inverso)
    7. ¿De qué marca es?        → los 3 primeros bytes de la MAC                (fabricante_de)
    8. Juntar todo por IP y deducir el tipo de equipo                          (relevar)

Nada está fijo en el código: la interfaz, la red, el router y los tipos de servicio se descubren
en el momento, así que funciona en cualquier red (tu casa, la oficina, un aula).

Importante: el escaneo pasivo (pasos 1, 2, 4, 5 y 6) solo pregunta cosas que la red responde sola.
El barrido (paso 3) es descubrimiento activo, como `nmap -sn`: usalo solo en tu red o con autorización.
"""
from __future__ import annotations   # permite escribir tipos como «str | None» en Python 3.8 y 3.9

import csv                                   # leer y escribir el inventario (archivo .csv, se abre con Excel)
import ipaddress                             # entender direcciones IP y redes (por ejemplo 192.168.0.0/24)
import os
import platform                              # saber si estamos en Mac («Darwin») o en Linux
import re                                    # expresiones regulares: buscar datos dentro del texto de un comando
import resource                              # consultar límites del sistema (archivos abiertos)
import shutil                                # saber si un comando existe (shutil.which)
import socket
import subprocess                            # ejecutar comandos del sistema (arp, ping, dns-sd…)
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor   # hacer muchas consultas a la vez (en paralelo)
from dataclasses import dataclass, field     # clases simples para guardar datos (Red, Equipo, Anuncio)
from datetime import datetime
from pathlib import Path

# ───────────────────────── configuración ─────────────────────────
ES_MAC = platform.system() == "Darwin"       # True en macOS, False en Linux
CARPETA = Path(__file__).resolve().parent    # la carpeta donde están los programas
BASE_FABRICANTES = CARPETA / "fabricantes-mac.txt"   # copia de https://www.wireshark.org/download/automated/data/manuf
INVENTARIO = CARPETA / "inventario-activos.csv"      # lo crea escanear-red.py
REGISTRO = CARPETA / "alertas-red.log"               # lo escribe vigilar-red.py
ESCUCHA = 4          # segundos que se escucha cada consulta de anuncios (los equipos tardan en contestar)

# Cada comando que se ejecuta en paralelo abre varios archivos (sus canales de entrada y salida).
# La terminal tiene un límite de archivos abiertos (en macOS suele ser 256; se ve con «ulimit -n»).
# Por eso la cantidad de comandos simultáneos se calcula a partir de ese límite, para no pasarse.
try:
    _limite_archivos = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
except (ValueError, OSError):
    _limite_archivos = 256
MAX_SIMULTANEOS = max(8, min(64, (_limite_archivos - 40) // 4))
MAX_BARRIDO = 1024   # tope de direcciones para el barrido (una red de empresa puede tener miles)

# Columnas del inventario de activos (inventario-activos.csv).
# «Autorizado» y «Responsable» las completa una persona: el programa nunca las pisa.
COLUMNAS_INVENTARIO = ["MAC", "IP", "Nombre", "Fabricante", "Tipo", "Modelo", "Sistema", "Servicios",
                       "Primera vez", "Última vez", "Autorizado", "Responsable"]

# Los equipos anuncian sus servicios con un «tipo» estándar (DNS-SD). Ejemplos:
#   _airplay._tcp      → acepta video por AirPlay (televisores, Mac)
#   _googlecast._tcp   → acepta video por Chromecast
#   _ipp._tcp          → es una impresora
# Esta tabla traduce cada tipo a una etiqueta en castellano y a una «clase» que ayuda a deducir qué equipo es.
# Si aparece un tipo que no está acá, igual se muestra, con su nombre técnico.
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
# Los equipos de Apple anuncian un identificador de modelo, por ejemplo «Mac15,3» o «iPhone15,2».
# Con el comienzo de ese identificador se sabe qué tipo de equipo es.
MODELOS_APPLE = (("Mac", "Computadora Apple"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                 ("AppleTV", "Apple TV"), ("AudioAccessory", "HomePod"))

# El TTL («time to live») es un número que cada sistema pone en sus paquetes. Cada router que atraviesa
# el paquete le resta 1. En la red local no hay routers en el medio, así que llega el valor original,
# y ese valor depende del sistema operativo. Es una pista, no una prueba: se puede cambiar.
SISTEMA_POR_TTL = {64: "Linux, Android o Apple", 128: "Windows", 255: "Equipo de red"}


# ───────────────────────── utilidades ─────────────────────────
def correr(cmd, segundos=15, cortar=False):
    """Ejecuta un comando del sistema y devuelve lo que escribió en pantalla, como texto.

    Ejemplo:  correr(["ping", "-c", "1", "192.168.0.1"])  →  "PING 192.168.0.1 ... ttl=64 time=4.1 ms ..."

    Algunos comandos, como dns-sd, no terminan nunca: se quedan escuchando la red. Con cortar=True
    se los deja escuchar `segundos` y después se los corta, como cuando uno aprieta Control + C.
    Si el comando no existe o falla, devuelve "" (texto vacío) para que el programa siga igual.
    """
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
    """Aplica `funcion` a cada elemento, varios a la vez, y devuelve los resultados en el mismo orden.

    Hacer 254 pings uno detrás del otro tardaría minutos; en paralelo tarda segundos.
    Ejemplo:  en_paralelo(sondear, ["192.168.0.1", "192.168.0.7"])  →  [resultado_1, resultado_7]
    """
    elementos = list(elementos)
    if not elementos:
        return []
    with ThreadPoolExecutor(min(hilos or MAX_SIMULTANEOS, MAX_SIMULTANEOS, len(elementos))) as ex:
        return list(ex.map(funcion, elementos))


def normalizar_mac(mac):
    """Deja todas las MAC con el mismo formato, para poder compararlas.

    La Mac muestra «a4:2b:b0:c:8:60» (sin ceros) y Windows «A4-2B-B0-0C-08-60».
    Las dos quedan como «a4:2b:b0:0c:08:60».
    """
    return ":".join(x.zfill(2) for x in mac.lower().replace("-", ":").split(":"))


def es_ip_de_equipo(ip):
    """True si la IP puede ser de un equipo. Descarta las direcciones especiales:

    224.x a 239.x (multicast, avisos a un grupo), 127.x (la propia computadora),
    169.254.x (sin configuración) y las que terminan en .255 (difusión a toda la red).
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and not (a.is_multicast or a.is_loopback or a.is_link_local or ip.endswith(".255"))


def ahora():
    return datetime.now().strftime("%d/%m/%Y %H:%M")


# ───────────────────────── paso 1 · ¿dónde estoy? ─────────────────────────
@dataclass
class Red:
    """Los datos de esta computadora y de la red a la que está conectada."""
    interfaz: str = ""   # la placa de red que se usa para salir a internet, por ejemplo «en0» (Wi-Fi en Mac)
    ip: str = ""         # la IP de esta computadora, por ejemplo 192.168.0.15
    mac: str = ""        # la MAC de esta computadora
    red: ipaddress.IPv4Network | None = None   # la red completa, por ejemplo 192.168.0.0/24 (254 direcciones)
    router: str = ""     # la puerta de enlace: por donde sale todo a internet, por ejemplo 192.168.0.1
    dns: list = field(default_factory=list)    # los servidores que traducen nombres a IP
    wifi: str = ""       # seguridad y canal del Wi-Fi, si se está por Wi-Fi
    equipo: str = ""     # marca y modelo de esta computadora
    sistema: str = ""    # sistema operativo de esta computadora
    proxy: int = 0       # direcciones por las que responde una misma MAC (proxy ARP, ver quitar_proxy)


def leer_red():
    """Averigua dónde está parada esta computadora: su IP, su red, su router y su DNS.

    En Mac usa estos comandos (se pueden probar a mano):
        route -n get default   →  «gateway: 192.168.0.1» e «interface: en0»
        ifconfig en0           →  «inet 192.168.0.15 netmask 0xffffff00» y «ether 32:65:c7:…»
        scutil --dns           →  «nameserver[0] : 192.168.0.1»
    En Linux, los equivalentes son «ip route», «ip addr» y el archivo /etc/resolv.conf.
    """
    r = Red()
    if ES_MAC:
        ruta = correr(["route", "-n", "get", "default"])
        r.router = _buscar(r"gateway: ([\d.]+)", ruta)
        r.interfaz = _buscar(r"interface: (\S+)", ruta)
        cfg = correr(["ifconfig", r.interfaz]) if r.interfaz else ""
        r.ip = _buscar(r"inet ([\d.]+)", cfg)
        mac = _buscar(r"ether ([0-9a-f:]+)", cfg)
        r.mac = normalizar_mac(mac) if mac else ""
        # La máscara viene en hexadecimal: 0xffffff00 tiene 24 bits en 1, o sea una red /24 (254 equipos posibles).
        mascara = _buscar(r"netmask (0x[0-9a-f]+)", cfg)
        prefijo = bin(int(mascara, 16)).count("1") if mascara else 24
        r.dns = list(dict.fromkeys(re.findall(r"nameserver\[\d+\] : (\S+)", correr(["scutil", "--dns"]))))[:3]
        # system_profiler da el modelo de la Mac («MacBook Pro», «Mac15,3») y los datos del Wi-Fi.
        perfil = correr(["system_profiler", "SPHardwareDataType", "SPAirPortDataType"], 30)
        r.equipo = " ".join(x for x in (_buscar(r"Model Name: (.+)", perfil),
                                        "(" + _buscar(r"Model Identifier: (.+)", perfil) + ")") if x.strip("()"))
        r.sistema = "macOS " + platform.mac_ver()[0]
        actual = perfil.split("Current Network Information:")[1][:700] if "Current Network Information:" in perfil else ""
        r.wifi = " · ".join(x for x in (_buscar(r"Security: (.+)", actual),
                                        "canal " + _buscar(r"Channel: (.+)", actual) if "Channel:" in actual else "",
                                        _buscar(r"PHY Mode: (.+)", actual)) if x)
    else:
        # «ip route get 1.1.1.1» pregunta: si quisiera llegar a internet, ¿por dónde saldría?
        # Responde algo como «1.1.1.1 via 192.168.0.1 dev wlan0 src 192.168.0.15».
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
        r.red = ipaddress.ip_network(f"{r.ip}/{prefijo}", strict=False)   # 192.168.0.15/24 → 192.168.0.0/24
    return r


def _buscar(patron, texto):
    """Busca un dato dentro del texto de un comando con una expresión regular.

    Ejemplo:  _buscar(r"gateway: ([\\d.]+)", "gateway: 192.168.0.1")  →  "192.168.0.1"
    Lo que está entre paréntesis en el patrón es lo que se devuelve. Si no lo encuentra, devuelve "".
    """
    m = re.search(patron, texto)
    return m.group(1).strip() if m else ""


def trafico_propio(interfaz):
    """Bytes recibidos y enviados por esta computadora desde que se encendió.

    Ojo: desde una computadora solo se puede medir su propio tráfico. Cuánto tráfico mueve cada
    equipo de la red lo sabe el router o el firewall (en una empresa, con registros de flujos como NetFlow).
    """
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
    """24000000000 → «22 GB»."""
    for unidad in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unidad}"
        n /= 1024
    return f"{n:.0f} PB"


# ───────────────────────── pasos 2 y 3 · ¿quién está en la red? ─────────────────────────
def leer_vecinos():
    """Lee la tabla ARP: la «agenda» que une cada IP con su MAC. Devuelve {ip: mac}.

    Cuando una computadora quiere hablar con otra de su red, pregunta por difusión «¿quién tiene la
    192.168.0.7?» y el dueño contesta «yo, mi MAC es 94:e6:ba:…». La respuesta queda anotada un rato.
    Por eso la tabla solo tiene los equipos con los que esta computadora habló hace poco.

    Ejemplo de «arp -an» en Mac:
        ? (192.168.0.1) at a4:2b:b0:c:8:60 on en0 ifscope [ethernet]
        ? (192.168.0.9) at (incomplete) on en0 ifscope [ethernet]      ← preguntó y nadie contestó
    En Linux, «ip neigh» muestra:  192.168.0.1 dev wlan0 lladdr a4:2b:b0:0c:08:60 REACHABLE
    """
    vecinos = {}
    if ES_MAC:
        for l in correr(["arp", "-an"]).splitlines():
            m = re.search(r"\(([\d.]+)\) at ([0-9a-f:]+) on ", l)
            # «permanent» es la propia computadora: la agrega el sistema, no es un vecino.
            if m and "permanent" not in l and es_ip_de_equipo(m.group(1)):
                vecinos[m.group(1)] = normalizar_mac(m.group(2))
    else:
        for l in correr(["ip", "-4", "neigh"]).splitlines():
            m = re.match(r"([\d.]+) dev \S+ lladdr ([0-9a-f:]+) (\w+)", l)
            if m and m.group(3) not in ("FAILED", "INCOMPLETE") and es_ip_de_equipo(m.group(1)):
                vecinos[m.group(1)] = normalizar_mac(m.group(2))
    return vecinos


def quitar_proxy(vecinos, router):
    """Si una misma MAC responde por muchas IP, deja una sola. Devuelve cuántas quitó.

    En algunas redes (las de la nube, o routers con «proxy ARP») el router contesta por todas las
    direcciones, aunque no haya nadie. Sin este filtro, el programa vería 150 «equipos» que son uno solo.
    """
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
    """Todas las direcciones posibles de la red, menos la propia.

    En una red /24 (192.168.0.0/24) son 253: de la .1 a la .254, menos esta computadora.
    Si la red es enorme (una empresa puede tener una /16, con 65.534), se barren solo las 254 vecinas.
    """
    if not red.red:
        return []
    zona = red.red if red.red.num_addresses <= MAX_BARRIDO else ipaddress.ip_network(f"{red.ip}/24", strict=False)
    return [str(h) for h in zona.hosts() if str(h) != red.ip]


def barrer(red):
    """Descubrimiento ACTIVO: un ping a cada dirección de la red (lo mismo que hace «nmap -sn»).

    No importa si contestan el ping: para enviarlo, la computadora primero tiene que preguntar la MAC
    del destino, y cada equipo encendido contesta esa pregunta. Así todos quedan en la tabla ARP.
    Las direcciones donde no hay nadie quedan como «(incomplete)» un par de minutos.

    Desde el lado del defensor: un equipo que pregunta por todas las direcciones en pocos segundos es
    un comportamiento típico de descubrimiento de la red, y muchos sistemas de detección lo marcan como alerta.
    """
    espera = ["-W", "1000"] if ES_MAC else ["-W", "1"]   # esperar como máximo 1 segundo cada respuesta
    en_paralelo(lambda ip: correr(["ping", "-c", "1", *espera, ip], 3), direcciones_a_barrer(red))


# ───────────────────────── paso 4 · ¿responde? ¿qué sistema usa? ─────────────────────────
def sondear(ip):
    """Dos pings a una IP. Devuelve (ip, (responde, latencia en ms, TTL)).

    Ejemplo de respuesta de «ping -c 2 192.168.0.7»:
        64 bytes from 192.168.0.7: icmp_seq=0 ttl=64 time=4.878 ms
        64 bytes from 192.168.0.7: icmp_seq=1 ttl=64 time=9.428 ms
    - time es la latencia: cuánto tarda en ir y volver (en la red de casa, unos pocos milisegundos).
    - ttl=64 sugiere Linux, Android o Apple; 128, Windows; 255, un equipo de red.
    Son dos pings porque el primero muchas veces se pierde o tarda (el equipo se está despertando).
    Un celular bloqueado suele no contestar: «no responde» no significa «no está».
    """
    espera = ["-W", "1000"] if ES_MAC else ["-W", "1"]
    respuestas = re.findall(r"ttl=(\d+) time=([\d.]+)", correr(["ping", "-c", "2", "-i", "0.3", *espera, ip], 5))
    if not respuestas:
        return ip, (False, None, None)
    return ip, (True, min(float(t) for _, t in respuestas), int(respuestas[0][0]))


# ───────────────────────── paso 6 · ¿cómo se llama? ─────────────────────────
def nombre_inverso(ip, router):
    """El nombre de una IP («DNS inverso»): de 192.168.0.7 a «Living-TV.local».

    Primero le pregunta a la propia red por mDNS (cada equipo puede responder su nombre) y después
    al DNS del router, que a veces recuerda el nombre que cada equipo le dio al conectarse.
    A mano:  dig +short -x 192.168.0.7 @224.0.0.251 -p 5353
    """
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


# ───────────────────────── paso 5 · ¿qué anuncia cada equipo? ─────────────────────────
@dataclass
class Anuncio:
    """Un servicio que un equipo anuncia en la red. Ejemplo: el televisor dice «acepto AirPlay en el puerto 7000»."""
    ip: str
    host: str        # su nombre de red, por ejemplo «Living-TV.local»
    tipo: str        # el tipo de servicio, por ejemplo «_airplay._tcp»
    instancia: str   # el nombre con el que se presenta, por ejemplo «TV del living»
    puerto: str      # el número de puerta por el que atiende ese servicio, por ejemplo 7000
    datos: dict      # la «ficha»: fabricante, modelo, nombre amigable


# Datos de la ficha que sirven para identificar el equipo (cada fabricante usa nombres distintos)
CLAVES_FICHA = "model|md|manufacturer|fn|ty|usb_MDL|usb_MFG|product"


def leer_anuncios():
    """Todo lo que los equipos anuncian por mDNS/DNS-SD, sea cual sea el tipo de servicio.

    mDNS (DNS multicast) es la forma en que los equipos se presentan solos en una red de casa u oficina:
    así el celular encuentra la impresora o el televisor sin que nadie configure nada.
    Para un analista es oro: el equipo dice qué es, de qué marca y qué servicios ofrece.
    """
    return _anuncios_mac() if ES_MAC else _anuncios_linux()


def _anuncios_mac():
    """Los anuncios en Mac, con el comando dns-sd. Son los mismos pasos que se hacen a mano:

        dns-sd -B _services._dns-sd._udp local.       → qué TIPOS de servicio hay  (_airplay, _ipp, …)
        dns-sd -B _airplay._tcp local.                → qué EQUIPOS ofrecen uno    («TV del living»)
        dns-sd -L "TV del living" _airplay._tcp local. → su FICHA: «can be reached at Living-TV.local.:7000»
                                                         y datos como «manufacturer=Samsung model=QN55»
        dns-sd -G v4 Living-TV.local                  → su IP (192.168.0.7)
    """
    def quitar_escapes(v):
        # dns-sd escribe los espacios como «\032» o «\ ». Ejemplo: «TV\032del\032living» → «TV del living»
        v = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), v)
        return re.sub(r"\\(.)", r"\1", v).strip("()")

    # 1. Los tipos de servicio que se anuncian. Cada renglón de la respuesta se ve así:
    #    17:00:37.566  Add  3  12 .   _tcp.local.   _airplay      → tipo «_airplay._tcp»
    tipos = {f"{m.group(2)}.{m.group(1)}" for m in re.finditer(
        r"\sAdd\s+\d+\s+\d+\s+\S+\s+(_tcp|_udp)\.\S*\s+(_[\w-]+)",
        correr(["dns-sd", "-B", "_services._dns-sd._udp", "local."], ESCUCHA, cortar=True))}

    # 2. Los equipos que ofrecen cada tipo. Renglón de ejemplo:
    #    17:00:40.112  Add  2  12 local.   _airplay._tcp.   TV del living
    def instancias(tipo):
        salida = correr(["dns-sd", "-B", tipo, "local."], ESCUCHA, cortar=True)
        return [(tipo, m.group(1).strip()) for m in re.finditer(r"\sAdd\s+\d+\s+\d+\s+\S+\s+\S+\s+(.+)$", salida, re.M)]

    # 3. La ficha de cada equipo: su nombre de red, el puerto y los datos de fabricante y modelo.
    def ficha(par):
        tipo, instancia = par
        for _ in range(2):                                    # un equipo dormido puede no contestar la primera vez
            salida = correr(["dns-sd", "-L", instancia, tipo, "local."], ESCUCHA, cortar=True)
            m = re.search(r"can be reached at (\S+?)\.?:(\d+)", salida)
            if m:
                break
        datos = {k: quitar_escapes(v) for k, v in re.findall(r"\b(" + CLAVES_FICHA + r")=((?:\\.|[^ \n])+)", salida)}
        return tipo, instancia, (m.group(1) if m else ""), (m.group(2) if m else ""), datos

    # 4. La IP de cada nombre de red. Renglón de ejemplo:
    #    17:00:45.010  Add  40000002  12  Living-TV.local.   192.168.0.7   120
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
    """Los anuncios en Linux, con avahi-browse, que hace los cuatro pasos de dns-sd en un solo comando.

    Con -p cada renglón viene separado por «;». Ejemplo de un renglón resuelto («=»):
        =;wlan0;IPv4;TV del living;_airplay._tcp;local;Living-TV.local;192.168.0.7;7000;"manufacturer=Samsung" "model=QN55"
    """
    anuncios = []
    for l in correr(["avahi-browse", "-a", "-r", "-t", "-p", "-k"], 25).splitlines():
        c = l.split(";")
        if c[0] == "=" and len(c) >= 10 and c[2] == "IPv4":
            datos = dict(re.findall(r'"(' + CLAVES_FICHA + r')=([^"]*)"', c[9]))
            instancia = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), c[3])
            anuncios.append(Anuncio(c[7], c[6], c[4], instancia, c[8], datos))
    return anuncios


# ───────────────────────── paso 7 · cada equipo y su fabricante ─────────────────────────
@dataclass
class Equipo:
    """Todo lo que se sabe de un equipo de la red. Es una fila de la tabla."""
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
    servicios: dict = field(default_factory=dict)   # etiqueta → puerto, por ejemplo {"AirPlay": "7000"}
    clases: set = field(default_factory=set)        # clases de equipo que sugieren sus servicios

    @property
    def mac_privada(self):
        """True si la MAC es inventada (privada), no la de fábrica.

        Los celulares y muchas computadoras inventan una MAC distinta para cada Wi-Fi, para que no los
        rastreen (en el iPhone se llama «Dirección Wi-Fi privada»). Esas MAC tienen encendido un bit
        especial, «administrada localmente», que se ve en el segundo carácter: 2, 6, A o E.
            fe:7f:34:…  →  e  →  privada          94:e6:ba:…  →  4  →  de fábrica (Samsung)
        """
        return bool(self.mac) and bool(int(self.mac[:2], 16) & 0b10)

    @property
    def clave(self):
        """Lo que identifica al equipo en el inventario: su MAC (la IP puede cambiar)."""
        return self.mac or "ip:" + self.ip


def cargar_fabricantes():
    """Carga la base de fabricantes: {primeros 3 bytes de la MAC: fabricante}.

    Cada fabricante de placas de red compra a la IEEE un bloque de direcciones. Los primeros 3 bytes
    de la MAC dicen quién fabricó la placa. Renglón de ejemplo de fabricantes-mac.txt:
        94:E6:BA    SamsungElect    Samsung Electronics Co.,Ltd
    """
    tabla = {}
    if BASE_FABRICANTES.exists():
        for l in BASE_FABRICANTES.read_text(errors="ignore").splitlines():
            partes = l.split("\t")
            if len(partes) > 1 and len(partes[0].strip()) == 8:      # bloques de 3 bytes: AA:BB:CC
                tabla[partes[0].strip().lower()] = partes[-1].strip()
    return tabla


def fabricante_de(equipo, tabla):
    """El fabricante de la placa de red, por los primeros 3 bytes de la MAC.

    Ejemplo: 94:e6:ba:… → «Samsung». Ojo: es el fabricante de la PLACA, no siempre la marca del aparato
    (una caja de TV puede traer una placa Wi-Fi de AMPAK). Si la MAC es privada, no se puede saber.
    """
    if not equipo.mac:
        return ""
    if equipo.mac_privada:
        return "privada"
    nombre = tabla.get(equipo.mac[:8], "desconocido")
    # Se acorta el nombre legal: «Samsung Electronics Co.,Ltd» → «Samsung»
    corto = re.sub(r"[,\s]+(Co\.?|Ltd\.?|Inc\.?|Corp\.?|Corporation|Technologies|Technology|Electronics|International)\b.*$", "", nombre)
    return corto.strip(" ,") or nombre


def _nombre_presentable(instancia):
    """Descarta lo que no sirve como nombre: códigos largos, direcciones MAC y nombres de aplicaciones.

    «TV del living» → se queda.   «a1b2c3d4e5f6a7b8c9d0e1f2» → se descarta.   «com.empresa.servicio» → se descarta.
    """
    nombre = re.sub(r"^[0-9A-Fa-f]{12}@", "", instancia).strip()     # AirPlay audio antepone la MAC: «A1B2C3D4E5F6@TV»
    if re.fullmatch(r"[0-9a-fA-F-]{16,}", nombre) or re.match(r"[0-9a-fA-F:]{17}@", nombre) or re.fullmatch(r"[a-z]{2,}(\.[\w-]+){2,}", nombre):
        return ""
    return nombre


def _tipo_de(equipo, red):
    """Deduce qué tipo de equipo es, con las pistas que hay, de la más segura a la más débil:

    1. Es esta computadora o el router (se sabe por la configuración de red).
    2. El modelo que anuncia («Mac15,3» → computadora Apple; «iPhone15,2» → iPhone).
    3. Los servicios que anuncia (impresión → impresora; Chromecast → TV).
    4. El fabricante de la placa, para equipos inteligentes (WiZ → lámpara; Tuya → dispositivo inteligente).
    5. Si solo se sabe que tiene MAC privada, probablemente sea un celular o una computadora.
    """
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
    # 4. El fabricante de la placa, para equipos inteligentes que casi nunca anuncian nada.
    fabricante = fabricante_de(equipo, _tabla_fabricantes()).lower()
    for marca, tipo in TIPO_POR_FABRICANTE:
        if marca in fabricante:
            return tipo
    return "Celular o computadora" if equipo.mac_privada else ""


# Equipos inteligentes que se reconocen por el fabricante de su placa de red (ejemplos frecuentes en casas).
TIPO_POR_FABRICANTE = (("wiz", "Lámpara inteligente"), ("signify", "Lámpara inteligente"), ("philips lighting", "Lámpara inteligente"),
                       ("tuya", "Dispositivo inteligente"), ("espressif", "Dispositivo inteligente"),
                       ("hikvision", "Cámara"), ("dahua", "Cámara"), ("ezviz", "Cámara"), ("ring", "Cámara o timbre"))
_TABLA = None


def _tabla_fabricantes():
    global _TABLA
    if _TABLA is None:
        _TABLA = cargar_fabricantes()
    return _TABLA


# ───────────────────────── paso 8 · juntar todo ─────────────────────────
def relevar(barrido=False, anuncios=True, avisar=lambda texto: None):
    """Hace todos los pasos y devuelve (red, lista de equipos ordenados por IP).

    barrido=True  → además saluda a todas las direcciones de la red (descubrimiento activo).
    anuncios=False → no escucha los anuncios (más rápido; lo usa la vigilancia continua).
    avisar         → una función para mostrar en qué paso va.
    """
    avisar("leyendo los datos de esta computadora y de la red")
    red = leer_red()
    if barrido:
        avisar(f"barrido activo: un ping a {len(direcciones_a_barrer(red))} direcciones")
        barrer(red)
    vecinos = leer_vecinos()
    red.proxy = quitar_proxy(vecinos, red.router)
    avisar(f"midiendo latencia y TTL de {len(vecinos)} equipos")
    sondeos = dict(en_paralelo(sondear, vecinos))       # primero el ping: también despierta a los equipos dormidos
    lista = []
    if anuncios:
        avisar("escuchando lo que los equipos anuncian")
        lista = [a for a in leer_anuncios() if a.ip and es_ip_de_equipo(a.ip)]
        # Un equipo puede anunciarse sin estar en la tabla ARP (esta computadora no habló con él):
        # se le hace ping para conocer su MAC, su latencia y su TTL.
        faltan = {a.ip for a in lista} - set(vecinos) - {red.ip}
        sondeos.update(en_paralelo(sondear, faltan))
        vecinos = {**dict.fromkeys(faltan, ""), **vecinos, **{ip: mac for ip, mac in leer_vecinos().items() if ip in vecinos or ip in faltan}}
    avisar("preguntando el nombre de cada equipo")
    nombres = dict(en_paralelo(lambda ip: nombre_inverso(ip, red.router), vecinos))

    # Una ficha por IP. Esta computadora se agrega aparte, con sus datos reales (no hace falta adivinarlos).
    equipos = {ip: Equipo(ip=ip, mac=mac) for ip, mac in vecinos.items()}
    if red.ip:
        equipos[red.ip] = Equipo(ip=red.ip, mac=red.mac, responde=True, modelo=red.equipo, sistema=red.sistema)

    # Se suman los anuncios a cada equipo. Un mismo equipo puede anunciar varios servicios
    # (por ejemplo, un televisor: AirPlay, Chromecast y Spotify) y presentarse con distintos nombres:
    # se cuenta qué nombre usa más veces y ese es el que se muestra.
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
        # El nombre más útil: el que el equipo anuncia («TV del living»); si no, su nombre de red;
        # «localhost» no sirve como nombre (algunos televisores lo usan).
        e.nombre = anunciado or ("" if en_red == "localhost" else en_red) or (socket.gethostname().split(".")[0] if ip == red.ip else "")
        e.tipo = _tipo_de(e, red)
    return red, sorted(equipos.values(), key=lambda e: ipaddress.ip_address(e.ip))


# ───────────────────────── presentación en pantalla ─────────────────────────
# Los colores se usan solo si la salida es una terminal (si se guarda en un archivo, van sin color).
COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
ROJO, AMARILLO, VERDE, GRIS, NEGRITA = "31", "33", "32", "90", "1"


def pintar(texto, codigo):
    return f"\033[{codigo}m{texto}\033[0m" if COLOR else texto


def mostrar_mac(mac, completa):
    """Para proyectar en clase, la MAC se muestra tapada: a4:2b:b0:0c:08:60 → a4:2b:b0:xx:xx:xx.

    Los 3 primeros bytes (el fabricante) quedan a la vista; los otros 3 identifican a ese equipo puntual.
    """
    return mac if completa or not mac else mac[:8] + ":xx:xx:xx"


def fila_de(e, fabricantes, mac_completa):
    """Convierte un equipo en una fila de la tabla. Cada dato aparece una sola vez."""
    # Si la marca anunciada ya figura como fabricante de la placa, no se repite en «Modelo».
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
    """Imprime una lista de diccionarios como tabla alineada. Las columnas vacías no se muestran."""
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
    """Imprime el resumen de esta computadora y de la red, antes de la tabla."""
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
    """Muestra en qué paso va, en un solo renglón que se va reescribiendo."""
    if sys.stderr.isatty():
        print(f"\r\033[K  … {texto}", end="", file=sys.stderr, flush=True)


def fin_progreso():
    if sys.stderr.isatty():
        print("\r\033[K", end="", file=sys.stderr, flush=True)


# ───────────────────────── inventario de activos ─────────────────────────
# El inventario es la lista oficial de lo que DEBERÍA estar en la red. En una empresa es el primer control
# de seguridad (CIS Control 1): no se puede proteger lo que no se sabe que existe.
# Se guarda en inventario-activos.csv, que se puede abrir con Excel o Google Sheets y editar a mano.

def leer_inventario():
    """Lee el inventario guardado: {MAC: fila}. Si un equipo no tiene MAC, la clave es «ip:…»."""
    if not INVENTARIO.exists():
        return {}
    with INVENTARIO.open(newline="", encoding="utf-8-sig") as archivo:
        return {(f["MAC"] or "ip:" + f["IP"]): f for f in csv.DictReader(archivo)}


def guardar_inventario(inventario):
    filas = sorted(inventario.values(), key=lambda f: ipaddress.ip_address(f["IP"]) if es_ip_de_equipo(f["IP"]) else ipaddress.ip_address("0.0.0.0"))
    with INVENTARIO.open("w", newline="", encoding="utf-8-sig") as archivo:   # utf-8-sig: Excel muestra bien los acentos
        escritor = csv.DictWriter(archivo, fieldnames=COLUMNAS_INVENTARIO)
        escritor.writeheader()
        escritor.writerows(filas)


def autorizado(fila):
    """True si en la columna «Autorizado» dice «sí» (con o sin tilde)."""
    return fila.get("Autorizado", "").strip().lower() in ("sí", "si")


def servicios_de(fila):
    """Los servicios guardados en el inventario, como conjunto: «AirPlay, Chromecast» → {"AirPlay", "Chromecast"}."""
    return {s.strip() for s in fila.get("Servicios", "").split(",") if s.strip()}


def registrar(inventario, equipos, fabricantes):
    """Suma al inventario los equipos relevados. Devuelve las claves de los que no estaban.

    - Un equipo nuevo entra como «pendiente» (salvo esta computadora, que entra autorizada).
    - Lo que cargó una persona («Autorizado», «Responsable») nunca se pisa.
    - «Primera vez» y «Última vez» dicen cuándo se lo vio por primera y por última vez.
    """
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
            # «Celular o computadora» sale solo de la MAC privada: no pisa un tipo mejor que ya se conocía.
            "Tipo": anterior.get("Tipo", "") if e.tipo in ("", "Celular o computadora") and anterior.get("Tipo") else e.tipo,
            "Modelo": fila["Modelo"] or anterior.get("Modelo", ""),
            "Sistema": e.sistema or anterior.get("Sistema", ""),
            "Servicios": ", ".join(sorted(servicios_de(anterior) | set(e.servicios))),
            "Primera vez": anterior["Primera vez"], "Última vez": ahora(),
            "Autorizado": anterior["Autorizado"], "Responsable": anterior.get("Responsable", ""),
        }
    return nuevas
