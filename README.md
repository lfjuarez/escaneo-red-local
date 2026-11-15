# Escaneo y vigilancia de la red local

Material de práctica del curso de Ciberseguridad.

Comandos y programas para ver qué hay conectado a una red y avisar si aparece algo que no corresponde.
Sirven en cualquier red, porque nada está fijo: todo se descubre en el momento.

- **`escanear-red`** genera la tabla de equipos y la guarda como **inventario de activos**.
- **`vigilar-red`** compara la red contra ese inventario y **avisa** lo que no debería estar.
- **`quien-es`** muestra la ficha de un equipo a partir de su IP: marca, modelo, servicios y sistema.

**Usalos solo en tu red o con autorización.** En Argentina, acceder sin autorización a un sistema es delito (ley 26.388). Y escanear una red ajena sin permiso puede violar sus políticas y traer consecuencias legales.

## Índice

1. [Por qué un analista hace esto](#1-por-qué-un-analista-hace-esto)
2. [Cómo descargarlo](#2-cómo-descargarlo)
3. [Windows](#3-windows)
4. [Mac](#4-mac)
5. [Linux](#5-linux)
6. [Qué muestran los programas](#6-qué-muestran-los-programas) (para los tres sistemas)
7. [Qué significa cada columna](#7-qué-significa-cada-columna)
8. [Conceptos](#8-conceptos)
9. [Qué avisa la vigilancia](#9-qué-avisa-la-vigilancia)
10. [Archivos](#10-archivos)
11. [Límites](#11-límites)

Todos los ejemplos usan datos **inventados**: una red `192.168.0.x` con el router en la `192.168.0.1`
y un televisor Samsung en la `192.168.0.7`. En tu red las IP, las MAC y los nombres van a ser otros.

---

## 1. Por qué un analista hace esto

Lo primero que hace un analista al llegar a una red es saber **qué hay conectado**. No se puede proteger lo que no se sabe que existe:
es el primer control de los CIS Controls (**inventario de activos**).

Un atacante hace exactamente lo mismo cuando accede a una red, y tiene nombre: **descubrimiento**
(táctica de descubrimiento de MITRE ATT&CK, técnica [T1018](https://attack.mitre.org/techniques/T1018/), que menciona justamente la tabla ARP).
No hay que confundirlo con el *reconocimiento*, que es lo que hace el atacante antes de acceder, desde afuera.
La diferencia es el permiso y para qué se usa.

El camino de este repositorio:

1. **A mano, comando por comando**, para entender de dónde sale cada dato.
2. **Monitorear a mano**: comparar la red de ahora con la de antes.
3. **Automatizarlo** con los programas, porque en una empresa hay cientos o miles de equipos.

## 2. Cómo descargarlo

En esta página, botón verde **Code › Download ZIP**. Descomprimí el archivo y abrí una terminal en esa carpeta
(cómo se hace en cada sistema está al principio de su sección).

También se puede hacer desde la terminal, en Windows (PowerShell), Mac o Linux:

```powershell
curl.exe -L -o red.zip https://github.com/lfjuarez/escaneo-red-local/archive/refs/heads/main.zip
```

```powershell
tar -xf red.zip
```

```powershell
cd escaneo-red-local-main
```

(En Mac y Linux, el primer comando es `curl` en lugar de `curl.exe`.)

Para los comandos sueltos **no hace falta descargar nada**: vienen con el sistema.

---

## 3. Windows

**Videos paso a paso (grabados en Windows 11, sin instalar nada):**
- [¿Qué hay en tu Wi-Fi? Los comandos a mano](https://youtu.be/Mt7j98wjvVQ) (2:44): secciones 3.2 y 3.3.
- [Tu red a fondo con un programa](https://youtu.be/3S51acOCR0Y) (1:53): descargar el repositorio, escanear, la ficha de un equipo y la vigilancia (sección 3.4).

### 3.1 Abrir la terminal

Menú de inicio, escribí `powershell` y abrí **Windows PowerShell**. Todos los comandos de esta sección funcionan ahí,
y también los programas de la sección 3.4. No hace falta instalar nada.
Si usás el Símbolo del sistema (cmd) en lugar de PowerShell, cambiá `Select-String "din|dyn"` por `findstr /i "din dyn"`: en PowerShell, `findstr` rompe los acentos.

### 3.2 Explorar la red a mano

| Mac | Windows |
|---|---|
| `arp -a` | `arp -a \| Select-String "din\|dyn"` |
| `curl` a macvendors | `curl.exe` a macvendors |
| `dns-sd -Z` (lo que anuncian los equipos por mDNS) | `UPnP.UPnPDeviceFinder` (lo que anuncian por UPnP) |
| `ping NOMBRE.local` | `Resolve-DnsName IP` y `ping NOMBRE.local` |
| — | Preguntarle al equipo por su ficha (`irm` a su puerto de control) |

**Paso 1 · Cuál es mi IP y cuál es el router** (solo mira la configuración)

```powershell
ipconfig | Select-String "IPv4|puerta|gateway"
```

`ipconfig` muestra la configuración de red; `Select-String` deja solo los renglones que importan
(«puerta» es para Windows en español y «gateway», para Windows en inglés).

```
   Dirección IPv4. . . . . . . . . . . . . . : 192.168.0.15
   Puerta de enlace predeterminada . . . . . : 192.168.0.1
```

Tu computadora es la `192.168.0.15` y el router, la `192.168.0.1`.
Si aparece otra IPv4 con la puerta de enlace vacía, es una placa de red virtual (por ejemplo, de WSL o de una máquina virtual): no le hagas caso.

**Paso 2 · Quién está en mi red** (solo mira)

```powershell
arp -a | Select-String "din|dyn"
```

`arp -a` muestra la **tabla ARP**: los equipos de tu red con los que tu computadora habló hace poco, cada uno con su IP y su MAC.
`Select-String` deja solo los **dinámicos**, que son equipos reales («dinámico» en Windows en español, «dynamic» en inglés).
Los **estáticos** que se ven con `arp -a` solo no son equipos: son direcciones especiales de la red (la que termina en 255 y las que empiezan con 224 o 239).

```
  192.168.0.1           a4-2b-b0-12-34-56     dinámico
  192.168.0.7           94-e6-ba-ab-cd-ef     dinámico
  192.168.0.9           fe-7f-34-11-22-33     dinámico
```

Elegimos uno para investigar: la `192.168.0.7`, con MAC `94-e6-ba-ab-cd-ef`.

**Paso 3 · De qué marca es** (consulta a un servicio de internet)

```powershell
curl.exe https://api.macvendors.com/94-e6-ba
```

Los **primeros 3 pares de la MAC** dicen quién fabricó la placa de red, y este comando se los pregunta a un servicio público.
En PowerShell hay que escribir `curl.exe`: `curl` a secas es otro comando.

```
Samsung Electronics Co.,Ltd
```

También se puede pegar `94-e6-ba` en el navegador, en https://macvendors.com.
Si el **segundo carácter** de la MAC es 2, 6, A o E (como `fe-7f-34`), contesta `Locally Administered Address`: es una **MAC privada**,
que el equipo inventa para que no lo rastreen (lo hacen casi todos los celulares), y no se puede saber la marca.

**Paso 4 · Qué anuncian los equipos de sí mismos** (envía una pregunta a toda la red, unos 10 segundos)

```powershell
(New-Object -ComObject UPnP.UPnPDeviceFinder).FindByType('upnp:rootdevice',0) | ft FriendlyName,ManufacturerName,ModelName
```

Windows pregunta a toda la red «¿quién está ahí?» (protocolo UPnP/SSDP) y cada equipo que se anuncia contesta con su ficha:
nombre, fabricante y modelo. Lo hacen televisores, decodificadores, routers, impresoras y consolas.

```
FriendlyName   ManufacturerName    ModelName
------------   ----------------    ---------
TV del living  Samsung Electronics QN55Q60
Router         TP-Link             Archer C6
```

La marca Samsung coincide con la del paso 3: la `192.168.0.7` es ese televisor, modelo `QN55Q60`.
Este comando no muestra la IP de cada equipo: se cruza con la marca que dio macvendors.

**Paso 5 · Su nombre en la red, y confirmar la IP**

```powershell
Resolve-DnsName 192.168.0.7
```

```
Name                       Type   TTL   Section    NameHost
----                       ----   ---   -------    --------
7.0.168.192.in-addr.arpa   PTR    120   Answer     Samsung.local
```

Y para confirmar que ese nombre es de esa IP, igual que en Mac:

```powershell
ping -n 2 Samsung.local
```

```
Haciendo ping a Samsung.local [192.168.0.7] con 32 bytes de datos:
Respuesta desde 192.168.0.7: bytes=32 tiempo=5ms TTL=64
```

`TTL=64` es una pista del sistema: 64 suele ser Linux, Android o Apple (un televisor Samsung usa Linux); 128, Windows; 255, equipos de red.
Si `Resolve-DnsName` dice «El nombre DNS no existe», el equipo no anuncia nombre (pasa con celulares y equipos inteligentes): no es un error.

**Paso 6 · Preguntarle al equipo qué es** (prueba un puerto y lee su ficha)

```powershell
Test-NetConnection 192.168.0.7 -Port 8001
```

Si dice `TcpTestSucceeded : True`, el puerto está abierto. El 8001 es la interfaz de control de los televisores Samsung, y se le puede pedir la ficha:

```powershell
(irm http://192.168.0.7:8001/api/v2/).device | fl name,modelName,type,OS
```

```
name      : TV del living
modelName : QN55Q60
type      : Samsung SmartTV
OS        : Tizen
```

El puerto abierto delata el tipo de equipo:

| Puerto abierto | Qué suele ser | Cómo leer su ficha |
|---|---|---|
| 8001 | Televisor Samsung | `(irm http://IP:8001/api/v2/).device \| fl name,modelName,type,OS` |
| 8008 y 8009 | Chromecast, Google TV, Android TV o decodificador | `irm http://IP:8008/setup/eureka_info \| fl name,ip_address` |
| 7000 | AirPlay (Apple TV, Mac o televisor compatible) | `curl.exe -s -I http://IP:7000/info` → `Server: AirTunes/…` |
| 80 | Router, cámara o impresora (página de administración) | `curl.exe -s -I http://IP` |
| 631 o 9100 | Impresora | — |
| 554 | Cámara (video) | — |

**Conclusión:** la `192.168.0.7` es un televisor Samsung QN55Q60 con sistema Tizen, y lo dijo el propio equipo.
Eso mismo ve un atacante que accede al Wi-Fi: por eso se inventaría la red y se separan los equipos inteligentes.

> Los pasos 1 a 3 solo miran. Los pasos 4 a 6 le preguntan cosas a los equipos: hacelos **solo en tu red**.
> Al proyectar, ojo: `arp -a` muestra las MAC completas, y los nombres de los equipos pueden tener nombres de personas.

### 3.3 Monitorear a mano

La idea de monitorear es simple: anotar qué hay hoy y comparar con lo que hay después.

**Guardar una foto de la red:**

```powershell
arp -a | Select-String "din|dyn" > antes.txt
```

**Más tarde, otra foto:**

```powershell
arp -a | Select-String "din|dyn" > ahora.txt
```

**Compararlas:**

```powershell
Compare-Object (Get-Content antes.txt) (Get-Content ahora.txt)
```

Si no muestra nada, la red está igual. Un renglón con `=>` es un equipo que **apareció**; con `<=`, uno que **ya no está**:

```
InputObject                                              SideIndicator
-----------                                              -------------
  192.168.0.23          2a-04-f6-aa-bb-cc     dinámico   =>
```

**Mirar la red cada 30 segundos** (se corta con Control + C):

```powershell
while ($true) { Get-Date; arp -a | Select-String "din|dyn"; Start-Sleep 30 }
```

Esto funciona, pero a mano no escala. Para eso están los programas.

### 3.4 Los programas (PowerShell)

Desde PowerShell, parado en la carpeta descomprimida:

| Paso | Qué hace | Comando |
|---|---|---|
| 1 | Escaneo inicial: genera la tabla y la guarda como inventario | `powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1` |
| 1 bis | Lo mismo, pero saludando a todas las direcciones (encuentra más equipos) | `powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1 -Barrido` |
| 2 | Aprobar todos los equipos del inventario (o editar la columna «Autorizado» en Excel) | `powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1 -Aprobar` |
| 3 | Vigilar: compara la red con el inventario y avisa | `powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1` |
| 4 | Vigilancia continua, una revisión cada 30 segundos (Control + C para cortar) | `powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1 -Cada 30` |
| — | La ficha de un equipo puntual, a partir de su IP: marca, modelo, servicios y sistema | `powershell -ExecutionPolicy Bypass -File .\quien-es.ps1 192.168.0.7` |

- `-ExecutionPolicy Bypass` permite correr el archivo **solo esa vez**; no cambia la configuración de Windows.
- `-MacCompleta` muestra las MAC completas. Por defecto van tapadas, para poder proyectar la pantalla.
- Funcionan con el PowerShell que trae Windows (5.1) y con PowerShell 7. No hace falta instalar nada.
- Windows no trae `dns-sd`, así que los programas consultan los anuncios mDNS por su cuenta (envían la pregunta a 224.0.0.251, puerto 5353, y leen las respuestas). Por eso el escaneo también muestra **Tipo**, **Modelo** y **Servicios**: por ejemplo, «TV o reproductor · Samsung DU7000 · Chromecast :8009».

---

## 4. Mac

### 4.1 Abrir la terminal

Abrí la app **Terminal** (Command + Espacio, escribí «Terminal»).
Para los programas, escribí `cd ` (con un espacio al final), arrastrá la carpeta descomprimida a la ventana y presioná Enter.

### 4.2 Explorar la red a mano

**Paso 1 · Cuál es mi IP y cuál es el router**

```bash
ipconfig getifaddr en0
```

```bash
route -n get default | grep gateway
```

El primero muestra tu IP en el Wi-Fi (`en0`); el segundo, la IP del router.

```
192.168.0.15
    gateway: 192.168.0.1
```

**Paso 2 · Quién está en mi red**

```bash
arp -a
```

Muestra la **tabla ARP**: los equipos de tu red con los que tu computadora habló hace poco, cada uno con su IP y su MAC.

```
? (192.168.0.1) at a4:2b:b0:12:34:56 on en0 ifscope [ethernet]
? (192.168.0.7) at 94:e6:ba:ab:cd:ef on en0 ifscope [ethernet]
? (192.168.0.9) at fe:7f:34:11:22:33 on en0 ifscope [ethernet]
? (192.168.0.40) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
```

Los renglones `(incomplete)` son direcciones donde nadie contestó, y los `permanent` no son equipos (son direcciones especiales).

**Para ver solo los equipos reales:**

```bash
arp -a | grep -v -e incomplete -e permanent
```

`grep -v` oculta los renglones que contienen esas palabras.
Elegimos uno para investigar: la `192.168.0.7`, con MAC `94:e6:ba:ab:cd:ef`.

**Paso 3 · De qué marca es**

```bash
curl https://api.macvendors.com/94:e6:ba
```

Los **primeros 3 pares de la MAC** dicen quién fabricó la placa de red. Este comando se los pregunta a un servicio público.

```
Samsung Electronics Co.,Ltd
```

**Ojo con los ceros:** macOS muestra las MAC sin los ceros iniciales de cada par (por ejemplo `0:1e:c2` en lugar de `00:1e:c2`).
Antes de consultar, completá con un 0 cada par de un solo carácter: con `0:1e:c2` el servicio responde «Multicast Address», y con `00:1e:c2`, la marca correcta.
Por eso en el ejemplo de arriba aparecen `1:0:5e:0:0:fb` y, más abajo, `2a:4:f6`.

También se puede buscar en el navegador, en https://macvendors.com.
Si el **segundo carácter** de la MAC es 2, 6, A o E (como `fe:7f:34`), es una **MAC privada** y contesta `Locally Administered Address`:
no se puede saber la marca.

**Paso 4 · Qué es exactamente**

```bash
dns-sd -Z _googlecast._tcp local.
```

Le pregunta a la red qué equipos reciben video por Chromecast. Esperá 3 segundos y cortalo con **Control + C**.
Cada equipo aparece en tres renglones:

```
_googlecast._tcp        PTR   TV-del-living-a1b2c3._googlecast._tcp
TV-del-living-a1b2c3…   SRV   0 0 8009 a1b2c3d4-0000-1111-2222-333344445555.local.
TV-del-living-a1b2c3…   TXT   "fn=TV del living" "md=QN55Q60" ...
```

- **SRV**: su nombre de red, el que termina en `.local` (lo usamos en el paso 5).
- **TXT**: su ficha. `fn=` es el nombre y `md=` el modelo.

Para Mac, Apple TV y televisores con AirPlay:

```bash
dns-sd -Z _airplay._tcp local.
```

Ahí el modelo aparece como `model=`. Para ver **todos** los tipos de servicio que se anuncian en tu red:

```bash
dns-sd -B _services._dns-sd._udp local.
```

**Paso 5 · Confirmar que es la misma IP**

```bash
ping -c 1 a1b2c3d4-0000-1111-2222-333344445555.local
```

Le hace ping al nombre `.local` del paso 4. En la primera línea, entre paréntesis, aparece su IP:

```
PING a1b2c3d4-0000-1111-2222-333344445555.local (192.168.0.7): 56 data bytes
64 bytes from 192.168.0.7: icmp_seq=0 ttl=64 time=5.1 ms
```

Es la `192.168.0.7`, la misma del paso 2. **Conclusión: esa IP es un televisor Samsung, modelo QN55Q60.**
De paso, `ttl=64` es una pista del sistema: 64 suele ser Linux, Android o Apple; 128, Windows.

### 4.3 Monitorear a mano

**Guardar una foto de la red, más tarde otra, y compararlas:**

```bash
arp -a | grep -v -e incomplete -e permanent > antes.txt
```

```bash
arp -a | grep -v -e incomplete -e permanent > ahora.txt
```

```bash
diff antes.txt ahora.txt
```

`diff` muestra solo lo que cambió. Un renglón con `>` es algo que **apareció** (por ejemplo, un equipo nuevo); con `<`, algo que **ya no está**.
Si no muestra nada, no cambió nada.

```
> ? (192.168.0.23) at 2a:4:f6:aa:bb:cc on en0 ifscope [ethernet]
```

**Mirar la red cada 30 segundos** (se corta con Control + C):

```bash
while true; do date; arp -a | grep -v -e incomplete -e permanent; sleep 30; done
```

### 4.4 Los programas (Python)

Desde la Terminal, parado en la carpeta descomprimida:

| Paso | Qué hace | Comando |
|---|---|---|
| 1 | Escaneo inicial: genera la tabla y la guarda como inventario | `python3 escanear-red.py` |
| 1 bis | Lo mismo, pero saludando a todas las direcciones (encuentra más equipos) | `python3 escanear-red.py --barrido` |
| 2 | Aprobar todos los equipos del inventario (o editar la columna «Autorizado» en Excel o Numbers) | `python3 escanear-red.py --aprobar` |
| 3 | Vigilar: compara la red con el inventario y avisa | `python3 vigilar-red.py` |
| 4 | Vigilancia continua, una revisión cada 30 segundos (Control + C para cortar) | `python3 vigilar-red.py --cada 30` |
| — | La ficha de un equipo puntual, a partir de su IP | `python3 quien-es.py 192.168.0.7` |

- `--mac` muestra las MAC completas. Por defecto van tapadas, para poder proyectar la pantalla.
- La primera vez que corras `python3` puede aparecer un aviso para instalar las herramientas de línea de comandos de Apple: aceptalo.
- Para leer cómo funciona cada uno: `less escanear-red.py` (se sale con `q`). Están comentados paso a paso.

---

## 5. Linux

### 5.1 Abrir la terminal

Clic derecho en la carpeta descomprimida › **Abrir en una terminal** (o Control + Alt + T y `cd` a la carpeta).

### 5.2 Explorar la red a mano

**Paso 1 · Cuál es mi IP y cuál es el router**

```bash
ip -4 -br addr
```

```bash
ip route | grep default
```

El primero muestra tus direcciones IP por placa de red; el segundo, la IP del router (después de `via`).

```
lo               UNKNOWN        127.0.0.1/8
wlan0            UP             192.168.0.15/24
default via 192.168.0.1 dev wlan0 proto dhcp metric 600
```

**Paso 2 · Quién está en mi red**

```bash
ip neigh
```

Es la tabla ARP en Linux (ahí se llama «vecinos»). Cada renglón es un equipo con su IP (`192.168.0.7`) y su MAC (después de `lladdr`).

```
192.168.0.1 dev wlan0 lladdr a4:2b:b0:12:34:56 REACHABLE
192.168.0.7 dev wlan0 lladdr 94:e6:ba:ab:cd:ef STALE
192.168.0.9 dev wlan0 lladdr fe:7f:34:11:22:33 STALE
192.168.0.40 dev wlan0 FAILED
```

`REACHABLE` es un equipo que respondió hace instantes; `STALE`, uno que respondió hace un rato; `FAILED`, una dirección donde nadie contestó.

**Para ver solo los equipos reales:**

```bash
ip -4 neigh | grep lladdr
```

Deja solo los renglones de IPv4 que tienen MAC. (Si tenés instalado `net-tools`, también funciona `arp -a`, igual que en Mac.)

**Paso 3 · De qué marca es**

```bash
curl https://api.macvendors.com/94:e6:ba
```

Igual que en Mac: los **primeros 3 pares de la MAC** dicen el fabricante. Si el segundo carácter es 2, 6, A o E, es una **MAC privada**.

```
Samsung Electronics Co.,Ltd
```

**Paso 4 · Qué es exactamente**

```bash
avahi-browse -art
```

Escucha todo lo que los equipos anuncian de sí mismos (mDNS) y lo muestra resuelto: nombre, IP, puerto y la ficha (`txt`) con el modelo.
Termina solo después de unos segundos. Si no lo tenés: `sudo apt install avahi-utils` (Ubuntu y Debian).

```
=  wlan0 IPv4 TV-del-living-a1b2c3     _googlecast._tcp     local
   hostname = [a1b2c3d4-0000-1111-2222-333344445555.local]
   address = [192.168.0.7]
   port = [8009]
   txt = ["fn=TV del living" "md=QN55Q60" ...]
```

Acá la IP ya viene en el anuncio (`address`): **la 192.168.0.7 es un televisor Samsung, modelo QN55Q60.**
Para ver solo una IP: `avahi-browse -art | grep -B2 -A3 "192.168.0.7"`.

**Paso 5 · Si responde y qué sistema podría tener**

```bash
ping -c 2 192.168.0.7
```

```
64 bytes from 192.168.0.7: icmp_seq=1 ttl=64 time=5.1 ms
```

`time` es la latencia y `ttl=64`, la pista del sistema (64: Linux, Android o Apple; 128: Windows).

### 5.3 Monitorear a mano

```bash
ip -4 neigh | grep lladdr | cut -d' ' -f1,5 | sort > antes.txt
```

```bash
ip -4 neigh | grep lladdr | cut -d' ' -f1,5 | sort > ahora.txt
```

```bash
diff antes.txt ahora.txt
```

`cut` deja solo la IP y la MAC (sin el estado, que cambia solo) y `sort` las ordena, así `diff` compara lo que importa.
Un renglón con `>` es un equipo que **apareció**; con `<`, uno que **ya no está**.

```
> 192.168.0.23 2a:04:f6:aa:bb:cc
```

**Mirar la red cada 30 segundos** (se corta con Control + C):

```bash
watch -n 30 "ip -4 neigh | grep lladdr"
```

### 5.4 Los programas (Python)

Los mismos que en Mac, con `python3` (viene instalado en casi todas las distribuciones):

| Paso | Qué hace | Comando |
|---|---|---|
| 1 | Escaneo inicial | `python3 escanear-red.py` |
| 1 bis | Con barrido de todas las direcciones | `python3 escanear-red.py --barrido` |
| 2 | Aprobar el inventario | `python3 escanear-red.py --aprobar` |
| 3 | Vigilar | `python3 vigilar-red.py` |
| 4 | Vigilancia continua cada 30 segundos | `python3 vigilar-red.py --cada 30` |
| — | Ficha de una IP | `python3 quien-es.py 192.168.0.7` |

Para que aparezcan las columnas **Modelo** y **Servicios** hace falta `avahi-utils` (`sudo apt install avahi-utils`).

---

## 6. Qué muestran los programas

Lo mismo en los tres sistemas. Datos inventados:

```
ESCANEO DE LA RED · 14/11/2026 17:30
  Esta computadora  MacBook Air (Mac14,2) · macOS 15.5 · 192.168.0.15 · en0
  Red               192.168.0.0/24 · 254 direcciones posibles
  Router            192.168.0.1
  DNS en uso        192.168.0.1
  Wi-Fi             WPA2 Personal · canal 36 (5GHz, 80MHz) · 802.11ac
  Método            activo: barrido de 253 direcciones + tabla ARP + anuncios

IP            MAC                Fabricante  Nombre          Tipo              Modelo   Sistema                 Latencia     Servicios
192.168.0.1   a4:2b:b0:xx:xx:xx  TP-Link     router          Router                     Linux, Android o Apple  3 ms
192.168.0.7   94:e6:ba:xx:xx:xx  Samsung     TV del living   TV o reproductor  QN55     Linux, Android o Apple  5 ms         AirPlay :7000, Chromecast :8009
192.168.0.9   fe:7f:34:xx:xx:xx  privada                     Celular o computadora                                     no responde
192.168.0.12  3c:2a:f4:xx:xx:xx  Brother     Impresora-1     Impresora         HL-L2350 Linux, Android o Apple  12 ms        Impresión :631
192.168.0.15  32:65:c7:xx:xx:xx  privada     MacBook-de-Ana  Esta computadora  MacBook Air (Mac14,2)  macOS 15.5
```

Y la vigilancia, si alguien conecta un equipo que no está en el inventario:

```
ALERTAS (1)
IP            MAC                Fabricante  Nombre  Tipo             Motivo
192.168.0.23  2a:04:f6:xx:xx:xx  privada             Celular o computadora  no está en el inventario

Resultado: alertas: 1 · cambios: 0 · en regla: 5 · ausentes: 0 · alertas guardadas en alertas-red.log
```

`quien-es` (`quien-es.py` en Mac y Linux, `quien-es.ps1` en Windows) muestra la ficha de una IP, y al lado de cada dato, de dónde salió:

```
FICHA DE 192.168.0.7
  MAC            94:e6:ba:xx:xx:xx         arp -an | grep "(192.168.0.7)"
  Fabricante     Samsung                   primeros 3 bytes de la MAC (94:e6:ba) en fabricantes-mac.txt
  Responde       sí · 5 ms                 ping -c 2 192.168.0.7
  Sistema        Linux, Android o Apple    el TTL de esa respuesta (64)
  Nombre         TV del living             lo que el equipo anuncia por mDNS
  Modelo         Samsung QN55              la ficha de su anuncio (manufacturer, model)
  Servicios      AirPlay :7000, Chromecast :8009
  Tipo           TV o reproductor          deducido de su modelo y sus servicios
```

**Para practicar la vigilancia:** abrí `inventario-activos.csv`, borrá el renglón de un equipo (por ejemplo, tu celular) y corré `vigilar-red`.
Ese equipo va a aparecer como «no está en el inventario».

## 7. Qué significa cada columna

| Columna | Qué es | De dónde sale | Windows | Mac | Linux |
|---|---|---|---|---|---|
| **IP** | La dirección del equipo en tu red | La tabla ARP | `arp -a` | `arp -a` | `ip neigh` |
| **MAC** | El identificador de su placa de red | La tabla ARP | `arp -a` | `arp -a` | `ip neigh` |
| **Fabricante** | Quién fabricó la placa de red | Los 3 primeros pares de la MAC, en la base de la IEEE | `curl https://api.macvendors.com/94-e6-ba` | `curl https://api.macvendors.com/94:e6:ba` | igual que Mac |
| **Nombre** | Cómo se llama el equipo | Lo que anuncia, o la consulta inversa de nombre | `Resolve-DnsName IP` | `dig +short -x IP @224.0.0.251 -p 5353` | `avahi-resolve-address IP` |
| **Tipo** | Qué clase de equipo es | Se deduce de lo que anuncia y de su modelo | — | — | — |
| **Modelo** | Marca y modelo que el equipo dice tener | Su ficha de servicios (mDNS o UPnP) | `UPnP.UPnPDeviceFinder` (paso 4) o `quien-es.ps1` | `dns-sd -Z _airplay._tcp local.` | `avahi-browse -art` |
| **Sistema** | Una estimación del sistema operativo | El TTL de la respuesta al ping | `ping -n 2 IP` | `ping -c 2 IP` | `ping -c 2 IP` |
| **Latencia** | Cuánto tarda en responder | El tiempo de respuesta al ping | `ping -n 2 IP` | `ping -c 2 IP` | `ping -c 2 IP` |
| **Servicios** | Qué ofrece el equipo a la red, con su puerto | Los anuncios mDNS/DNS-SD | `quien-es.ps1`, o `Test-NetConnection IP -Port N` | `dns-sd -B _services._dns-sd._udp local.` | `avahi-browse -art` |

## 8. Conceptos

**Tabla ARP.** Cuando tu computadora quiere hablarle a otro equipo de la red, pregunta a todos «¿quién tiene la 192.168.0.7?» y el dueño contesta con su MAC.
La respuesta queda anotada un rato en la tabla ARP. Por eso esa tabla solo muestra los equipos con los que tu computadora habló hace poco, no todo lo que está conectado.

**Escaneo pasivo y activo.** El pasivo solo mira lo que ya pasó (la tabla ARP) y escucha lo que los equipos anuncian.
El activo (barrido) saluda a cada dirección de la red, como `nmap -sn`. Encuentra más equipos, pero deja huella:
en una red ajena, un equipo que pregunta por todas las direcciones en pocos segundos es una señal típica de descubrimiento de la red, y muchos sistemas de detección lo marcan.

**MAC privada.** Los celulares y muchas computadoras inventan una MAC distinta para cada Wi-Fi, para que no los rastreen.
Esas MAC tienen encendido un bit especial («administrada localmente»), que se ve en el segundo carácter: 2, 6, A o E. Por eso, de esos equipos no se puede saber el fabricante.

**TTL.** Cada sistema pone un número en sus paquetes: 64 suelen usar Linux, Android y Apple; 128, Windows; 255, los equipos de red. Es una pista, no una prueba.

**mDNS (DNS multicast).** Es la forma en que los equipos se presentan solos en una red de casa u oficina: así el celular encuentra la impresora o el televisor sin configurar nada.
Para un analista es muy útil, porque el equipo dice qué es, de qué marca y qué servicios ofrece.

**Inventario de activos.** La lista oficial de lo que debería estar en la red. Es el primer control de los CIS Controls: no se puede proteger lo que no se sabe que existe.

**ARP spoofing.** Un ataque de la red local: el atacante le dice a los demás equipos «yo soy el router» para que todo el tráfico pase por él (man in the middle).
Por eso `vigilar-red` avisa si la MAC del router cambia, o si otro equipo usa la misma MAC que el router.

## 9. Qué avisa la vigilancia

- **Alerta:** un equipo que no está en el inventario, o que está pero no autorizado.
- **Alerta:** señales de ARP spoofing: la MAC del router cambió, o un equipo usa la misma MAC que el router.
- **Cambio:** un equipo autorizado cambió de IP, de nombre o anuncia un servicio nuevo.
- **Ausente:** un equipo autorizado que ahora no se ve.

Las alertas también quedan escritas en `alertas-red.log`, como las recibiría un SIEM.
El programa termina con código 2 si hubo alertas, y con 0 si no, para poder usarlo en una tarea programada.

## 10. Archivos

| Archivo | Sistema | Para qué |
|---|---|---|
| `escanear-red.py`, `vigilar-red.py` | Mac y Linux | Los programas (Python 3.8 o más nuevo) |
| `quien-es.py` | Mac y Linux | De una IP a la ficha del equipo, con el comando del que sale cada dato |
| `quien-es.ps1` | Windows | Lo mismo en Windows. Como Windows no trae `dns-sd`, hace la consulta mDNS por su cuenta (está comentada paso a paso) |
| `red_local.py` | Mac y Linux | El motor que usan los tres: ahí está, comentado paso a paso, cómo se obtiene cada dato |
| `escanear-red.ps1`, `vigilar-red.ps1` | Windows | Los programas (PowerShell 5.1, el que trae Windows, o 7) |
| `RedLocal.ps1` | Windows | El motor de la versión de Windows, también comentado |
| `fabricantes-mac.txt` | Todos | La base de fabricantes por MAC. Tiene que estar junto a los programas |
| `inventario-activos.csv`, `alertas-red.log` | Todos | Los crea el programa. **Tienen los datos de tu red: no los compartas** |

## 11. Límites

- Sin barrido solo se ven los equipos con los que tu computadora habló hace poco.
- Un celular bloqueado no responde al ping y puede no decir su nombre: un solo escaneo no es un inventario completo. En una empresa, el inventario se mantiene de forma continua.
- El fabricante es el de la **placa de red**, no siempre la marca del aparato (una caja de TV puede traer una placa Wi-Fi de otro fabricante).
- Desde una computadora no se puede medir el tráfico de los demás equipos: eso lo sabe el router o el firewall.
- Los celulares cambian de MAC privada cada tanto (por red o por tiempo). Eso puede generar una alerta de «no está en el inventario» sin que haya un equipo nuevo: antes de alarmarse, revisar si es un celular conocido con otra MAC.

## Créditos

`fabricantes-mac.txt` es la base de fabricantes por MAC que publica Wireshark (https://www.wireshark.org/download/automated/data/manuf), generada a partir del registro público de la IEEE.
