# Escaneo y vigilancia de la red local

Material de práctica del curso de Ciberseguridad.

Dos programas para ver qué hay conectado a una red y avisar si aparece algo que no corresponde.
Sirven en cualquier red: nada está fijo, todo se descubre en el momento.

**Usalos solo en tu red o con autorización.** En Argentina, acceder sin autorización a un sistema es delito (ley 26.388).

## Cómo descargarlo

En esta página, botón verde **Code › Download ZIP**. Descomprimí el archivo, abrí una terminal en esa carpeta y seguí los pasos de la tabla.
En Mac: Terminal, escribí `cd ` (con un espacio), arrastrá la carpeta a la ventana y presioná Enter.
En Windows: abrí la carpeta, hacé clic en la barra de dirección, escribí `powershell` y presioná Enter.

| Paso | Qué hace | Mac y Linux | Windows (PowerShell) |
|---|---|---|---|
| 1 | Escaneo inicial: arma la tabla de equipos y la guarda como inventario | `python3 escanear-red.py` | `powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1` |
| 2 | Aprobar el inventario (o editar la columna «Autorizado» a mano) | `python3 escanear-red.py --aprobar` | `powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1 -Aprobar` |
| 3 | Vigilar: compara la red con el inventario y avisa | `python3 vigilar-red.py` | `powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1` |
| 4 | Vigilancia continua cada 30 segundos | `python3 vigilar-red.py --cada 30` | `powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1 -Cada 30` |

Opciones: `--barrido` (`-Barrido`) saluda a todas las direcciones de la red para encontrar más equipos;
`--mac` (`-MacCompleta`) muestra las MAC completas, que por defecto van tapadas para proyectar.

## Qué muestra de cada equipo

IP, MAC, fabricante de la placa (o «privada» si el equipo oculta su MAC), nombre, tipo de equipo, modelo,
sistema estimado por el TTL, latencia y, en Mac y Linux, los servicios que anuncia con su puerto.
Windows no trae una herramienta para leer esos anuncios, así que ahí faltan las columnas de modelo y servicios.

## Qué avisa la vigilancia

- **Alerta:** un equipo que no está en el inventario o que no está autorizado.
- **Alerta:** señales de ARP spoofing (la MAC del router cambió, o un equipo usa la misma MAC que el router).
- **Cambio:** un equipo autorizado cambió de IP, de nombre o anuncia un servicio nuevo.
- **Ausente:** un equipo autorizado que ahora no se ve.

Las alertas quedan además en `alertas-red.log`. El programa termina con código 2 si hubo alertas.

## Archivos

| Archivo | Para qué |
|---|---|
| `escanear-red.py`, `vigilar-red.py`, `red_local.py` | Mac y Linux (Python 3.8 o más nuevo; `red_local.py` es el motor compartido) |
| `escanear-red.ps1`, `vigilar-red.ps1`, `RedLocal.ps1` | Windows (PowerShell 5.1, el que trae Windows, o 7) |
| `fabricantes-mac.txt` | Base de fabricantes de la IEEE (la que usa Wireshark). Tiene que estar junto a los programas |
| `inventario-activos.csv`, `alertas-red.log` | Los crea el programa. **Tienen los datos de tu red: no los compartas** |

En Linux, para ver los servicios anunciados hace falta `avahi-utils` (`sudo apt install avahi-utils`).
En Mac, `python3` viene con las herramientas de línea de comandos de Apple.

## Límites

- Sin `--barrido` solo se ven los equipos con los que tu computadora habló hace poco.
- Un celular bloqueado no responde al ping y puede no decir su nombre: un solo escaneo no es un inventario completo.
- Desde una computadora no se puede medir el tráfico de los demás equipos: eso lo sabe el router o el firewall.

## Créditos

`fabricantes-mac.txt` es la base de fabricantes por MAC que publica Wireshark (https://www.wireshark.org/download/automated/data/manuf),
generada a partir del registro público de la IEEE.
