# Escaneo y vigilancia de la red local

Material de práctica del curso de Ciberseguridad.

Dos programas para ver qué hay conectado a una red y avisar si aparece algo que no corresponde.
Sirven en cualquier red, porque nada está fijo: todo se descubre en el momento.

- **`escanear-red`** arma la tabla de equipos y la guarda como **inventario de activos**.
- **`vigilar-red`** compara la red contra ese inventario y **avisa** lo que no debería estar.

**Usalos solo en tu red o con autorización.** En Argentina, acceder sin autorización a un sistema es delito (ley 26.388).

---

## 1. Cómo descargarlo

En esta página, botón verde **Code › Download ZIP**. Descomprimí el archivo y abrí una terminal en esa carpeta:

- **Mac:** abrí la app Terminal, escribí `cd ` (con un espacio al final), arrastrá la carpeta a la ventana y presioná Enter.
- **Windows:** abrí la carpeta, hacé clic en la barra de dirección de arriba, escribí `powershell` y presioná Enter.
- **Linux:** clic derecho en la carpeta › «Abrir en una terminal».

## 2. Explorar la red a mano, comando por comando

Antes de usar los programas conviene hacerlo a mano, para entender qué hacen por dentro.
El objetivo: tomar una IP de tu red y averiguar qué equipo es.

Los ejemplos usan datos **inventados**: una red `192.168.0.x` con un televisor Samsung en la `192.168.0.7`.
En tu red las IP, las MAC y los nombres van a ser otros.

### Paso 1 · Quién está en mi red

```bash
arp -a
```

Muestra los equipos de tu red con los que tu computadora habló hace poco: cada renglón es un equipo, con su IP y su MAC.

```
? (192.168.0.1) at a4:2b:b0:12:34:56 on en0 ifscope [ethernet]
? (192.168.0.7) at 94:e6:ba:ab:cd:ef on en0 ifscope [ethernet]
? (192.168.0.9) at fe:7f:34:11:22:33 on en0 ifscope [ethernet]
```

Elegimos uno para investigar: la `192.168.0.7`, con MAC `94:e6:ba:ab:cd:ef`.
Si aparecen renglones `(incomplete)` (direcciones donde no contestó nadie), se ocultan con `arp -a | grep -v incomplete`.

### Paso 2 · De qué marca es

```bash
curl https://api.macvendors.com/94:e6:ba
```

Los **primeros 3 números de la MAC** dicen quién fabricó la placa de red. Este comando se los pregunta a un servicio público.

```
Samsung Electronics Co.,Ltd
```

Si la MAC es privada (celulares y compus que la ocultan), contesta `Locally Administered Address`: no se puede saber la marca.
También se puede buscar en el navegador, en https://macvendors.com.

### Paso 3 · Qué es exactamente (Mac)

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

- **SRV**: su nombre de red, el que termina en `.local` (lo usamos en el paso 4).
- **TXT**: su ficha. `fn=` es el nombre y `md=` el modelo.

Para Mac, Apple TV y televisores con AirPlay: `dns-sd -Z _airplay._tcp local.` (ahí el modelo aparece como `model=`).
En Linux, el equivalente es `avahi-browse -art` (paquete `avahi-utils`).

### Paso 4 · Confirmar que es la misma IP

```bash
ping -c 1 a1b2c3d4-0000-1111-2222-333344445555.local
```

Le hace ping al nombre `.local` del paso 3. En la primera línea, entre paréntesis, aparece su IP:

```
PING a1b2c3d4-0000-1111-2222-333344445555.local (192.168.0.7): 56 data bytes
64 bytes from 192.168.0.7: icmp_seq=0 ttl=64 time=5.1 ms
```

Es la `192.168.0.7`, la misma del paso 1. **Conclusión: esa IP es un televisor Samsung, modelo QN55Q60.**
De paso, `ttl=64` es una pista del sistema: 64 suele ser Linux, Android o Apple; 128, Windows.

> En Windows: `arp -a` y `curl` funcionan igual; el ping es `ping -n 1 IP`. Windows no trae `dns-sd`, así que el paso 3 no se puede hacer sin instalar nada.

## 3. Monitorear a mano

La idea de monitorear es simple: anotar qué hay hoy y comparar con lo que hay después.

**Guardar una foto de la red:**

```bash
arp -a | grep -v incomplete > antes.txt
```

**Más tarde, otra foto, y compararlas:**

```bash
arp -a | grep -v incomplete > ahora.txt
```

```bash
diff antes.txt ahora.txt
```

`diff` muestra solo lo que cambió. Un renglón con `>` es algo que **apareció** (por ejemplo, un equipo nuevo); con `<`, algo que **ya no está**. Si no muestra nada, no cambió nada.

```
> ? (192.168.0.23) at 2a:04:f6:aa:bb:cc on en0 ifscope [ethernet]
```

**Mirar la red cada 30 segundos** (cortar con Control + C):

```bash
while true; do date; arp -a | grep -v incomplete; sleep 30; done
```

Esto funciona, pero a mano no escala: en una empresa hay cientos o miles de equipos. Para eso están los programas de este repositorio.

## 4. Automatizarlo: los programas

### Cómo se usan

| Paso | Qué hace | Mac y Linux | Windows (PowerShell) |
|---|---|---|---|
| 1 | Escaneo inicial: arma la tabla y la guarda como inventario | `python3 escanear-red.py` | `powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1` |
| 2 | Aprobar el inventario (o editar la columna «Autorizado» a mano) | `python3 escanear-red.py --aprobar` | `powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1 -Aprobar` |
| 3 | Vigilar: compara la red con el inventario y avisa | `python3 vigilar-red.py` | `powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1` |
| 4 | Vigilancia continua, una revisión cada 30 segundos | `python3 vigilar-red.py --cada 30` | `powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1 -Cada 30` |
| — | La ficha de un equipo puntual, a partir de su IP | `python3 quien-es.py 192.168.0.7` | (solo Mac y Linux) |

Opciones:

- `--barrido` (`-Barrido` en Windows): saluda a todas las direcciones de la red para encontrar más equipos.
- `--mac` (`-MacCompleta` en Windows): muestra las MAC completas. Por defecto van tapadas, para poder proyectar.

En Windows, `-ExecutionPolicy Bypass` permite correr el archivo solo esa vez; no cambia la configuración de Windows.

### Ejemplo de lo que vas a ver

Datos inventados, para que te ubiques:

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
192.168.0.9   fe:7f:34:xx:xx:xx  privada                     Celular o compu                                     no responde
192.168.0.12  3c:2a:f4:xx:xx:xx  Brother     Impresora-1     Impresora         HL-L2350 Linux, Android o Apple  12 ms        Impresión :631
192.168.0.15  32:65:c7:xx:xx:xx  privada     MacBook-de-Ana  Esta computadora  MacBook Air (Mac14,2)  macOS 15.5
```

Y la vigilancia, si alguien conecta un equipo que no está en el inventario:

```
ALERTAS (1)
IP            MAC                Fabricante  Nombre  Tipo             Motivo
192.168.0.23  2a:04:f6:xx:xx:xx  privada             Celular o compu  no está en el inventario

Resultado: alertas: 1 · cambios: 0 · en regla: 5 · ausentes: 0 · alertas guardadas en alertas-red.log
```

### De una IP a la ficha del equipo

`quien-es.py` muestra todo lo que se puede averiguar de una IP, y al lado de cada dato, el comando del que salió:

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

## 5. Qué significa cada columna (y cómo se obtiene)

| Columna | Qué es | De dónde sale | Probalo a mano |
|---|---|---|---|
| **IP** | La dirección del equipo en tu red | La tabla ARP de tu computadora | `arp -a` |
| **MAC** | El identificador de su placa de red | La misma tabla ARP | `arp -a` |
| **Fabricante** | Quién fabricó la placa de red | Los 3 primeros bytes de la MAC, en la base de la IEEE | buscá `94:E6:BA` en `fabricantes-mac.txt` |
| **Nombre** | Cómo se llama el equipo | Lo que el equipo anuncia, o la consulta inversa de nombre | `dig +short -x IP @224.0.0.251 -p 5353` (Mac) |
| **Tipo** | Qué clase de equipo es | Se deduce de lo que anuncia y de su modelo | — |
| **Modelo** | Marca y modelo que el equipo dice tener | Su «ficha» de servicios (mDNS) | `dns-sd -L "NOMBRE" _airplay._tcp local.` (Mac) |
| **Sistema** | Una estimación del sistema operativo | El TTL de la respuesta al ping | `ping -c 2 IP` |
| **Latencia** | Cuánto tarda en responder | El tiempo de respuesta al ping | `ping -c 2 IP` |
| **Servicios** | Qué ofrece el equipo a la red, con su puerto | Los anuncios mDNS/DNS-SD | `dns-sd -B _services._dns-sd._udp local.` (Mac) |

Windows no trae una herramienta para leer los anuncios de los equipos (mDNS), así que ahí faltan las columnas **Modelo** y **Servicios**.
En Linux, para verlas hace falta `avahi-utils` (`sudo apt install avahi-utils`).

## 6. Conceptos que aparecen

**Tabla ARP.** Cuando tu computadora quiere hablarle a otro equipo de la red, pregunta a todos «¿quién tiene la 192.168.0.7?» y el dueño contesta con su MAC. La respuesta queda anotada un rato en la tabla ARP. Por eso esa tabla solo muestra los equipos con los que tu computadora habló hace poco, no todo lo que está conectado.

**Escaneo pasivo y activo.** El pasivo solo mira lo que ya pasó (la tabla ARP) y escucha lo que los equipos anuncian. El activo (`--barrido`) saluda a cada dirección de la red, como `nmap -sn`. Encuentra más equipos, pero deja huella: en una red ajena, un equipo que pregunta por todas las direcciones en pocos segundos es una señal típica de reconocimiento, y muchos sistemas de detección lo marcan.

**MAC privada.** Los celulares y muchas computadoras inventan una MAC distinta para cada Wi-Fi, para que no los rastreen. Esas MAC tienen encendido un bit especial («administrada localmente»), que se ve en el segundo carácter: 2, 6, A o E. Por eso, de esos equipos no se puede saber el fabricante.

**TTL.** Cada sistema pone un número en sus paquetes: 64 suelen usar Linux, Android y Apple; 128, Windows; 255, los equipos de red. Es una pista, no una prueba.

**mDNS (DNS multicast).** Es la forma en que los equipos se presentan solos en una red de casa u oficina: así el celular encuentra la impresora o el televisor sin configurar nada. Para un analista es muy útil, porque el equipo dice qué es, de qué marca y qué servicios ofrece.

**Inventario de activos.** La lista oficial de lo que debería estar en la red. Es el primer control de los CIS Controls: no se puede proteger lo que no se sabe que existe.

**ARP spoofing.** Un ataque de la red local: el atacante le dice a los demás equipos «yo soy el router» para que todo el tráfico pase por él (man in the middle). Por eso `vigilar-red` avisa si la MAC del router cambia, o si otro equipo usa la misma MAC que el router.

## 7. Qué avisa la vigilancia

- **Alerta:** un equipo que no está en el inventario, o que está pero no autorizado.
- **Alerta:** señales de ARP spoofing: la MAC del router cambió, o un equipo usa la misma MAC que el router.
- **Cambio:** un equipo autorizado cambió de IP, de nombre o anuncia un servicio nuevo.
- **Ausente:** un equipo autorizado que ahora no se ve.

Las alertas también quedan escritas en `alertas-red.log`, como las recibiría un SIEM. El programa termina con código 2 si hubo alertas, y con 0 si no, para poder usarlo en una tarea programada.

**Para practicar:** abrí `inventario-activos.csv`, borrá el renglón de un equipo (por ejemplo, tu celular) y corré `vigilar-red`. Ese equipo va a aparecer como «no está en el inventario».

## 8. Archivos

| Archivo | Para qué |
|---|---|
| `escanear-red.py`, `vigilar-red.py` | Los programas para Mac y Linux (Python 3.8 o más nuevo) |
| `quien-es.py` | De una IP a la ficha del equipo, con el comando del que sale cada dato (Mac y Linux) |
| `red_local.py` | El motor que usan los tres: ahí está, comentado paso a paso, cómo se obtiene cada dato |
| `escanear-red.ps1`, `vigilar-red.ps1` | Los programas para Windows (PowerShell 5.1, el que trae Windows, o 7) |
| `RedLocal.ps1` | El motor de la versión de Windows |
| `fabricantes-mac.txt` | La base de fabricantes por MAC. Tiene que estar junto a los programas |
| `inventario-activos.csv`, `alertas-red.log` | Los crea el programa. **Tienen los datos de tu red: no los compartas** |

En Mac, la primera vez que corras `python3` puede aparecer un aviso para instalar las herramientas de línea de comandos de Apple: aceptalo.

## 9. Límites

- Sin `--barrido` solo se ven los equipos con los que tu computadora habló hace poco.
- Un celular bloqueado no responde al ping y puede no decir su nombre: un solo escaneo no es un inventario completo. En una empresa, el inventario se mantiene de forma continua.
- El fabricante es el de la **placa de red**, no siempre la marca del aparato (una caja de TV puede traer una placa Wi-Fi de otro fabricante).
- Desde una computadora no se puede medir el tráfico de los demás equipos: eso lo sabe el router o el firewall.

## Créditos

`fabricantes-mac.txt` es la base de fabricantes por MAC que publica Wireshark (https://www.wireshark.org/download/automated/data/manuf), generada a partir del registro público de la IEEE.
