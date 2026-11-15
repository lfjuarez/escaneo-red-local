# quien-es.ps1 — de una IP a la ficha del equipo (Windows)
# ========================================================
#
# Le das una IP de tu red y te muestra todo lo que se puede averiguar de ese equipo, dato por dato,
# y al lado de cada dato de dónde salió. Sirve para aprender el camino «a mano» y para investigar
# un equipo puntual que apareció en el escaneo (por ejemplo, uno que nadie reconoce).
#
# Uso (desde PowerShell, en la carpeta de los archivos):
#   powershell -ExecutionPolicy Bypass -File .\quien-es.ps1 192.168.0.7
#   powershell -ExecutionPolicy Bypass -File .\quien-es.ps1 192.168.0.7 -MacCompleta
#
# Ejemplo de lo que muestra (datos inventados):
#   FICHA DE 192.168.0.7
#     MAC          94:e6:ba:xx:xx:xx        tabla de vecinos (arp -a)
#     Fabricante   Samsung                  primeros 3 pares de la MAC en fabricantes-mac.txt
#     Responde     sí · 5 ms                ping -n 2 192.168.0.7
#     Sistema      Linux, Android o Apple   el TTL de esa respuesta (64)
#     Nombre       TV del living            lo que el equipo anuncia por mDNS
#     Modelo       QN55Q60                  la ficha de su anuncio (md=, model=)
#     Servicios    Chromecast :8009, AirPlay :7000
#     Tipo         TV o reproductor         deducido de sus servicios
#
# ¿Por qué hay una consulta mDNS escrita a mano?
#   En Mac existe el comando dns-sd y en Linux avahi-browse, que escuchan lo que los equipos anuncian
#   de sí mismos (mDNS, el «DNS multicast»). Windows no trae ninguno. Este script hace lo mismo que esos
#   comandos: envía una pregunta a la dirección multicast 224.0.0.251, puerto 5353, y lee las respuestas.
#
# Usalo solo en tu red o con autorización.

param(
    [Parameter(Mandatory = $true, Position = 0)][string]$IP,
    [switch]$MacCompleta
)

. (Join-Path $PSScriptRoot 'RedLocal.ps1')     # el motor: MAC privada, fabricante, pings y nombres

$direccion = $null
if (-not [System.Net.IPAddress]::TryParse($IP, [ref]$direccion) -or $IP.Split('.').Count -ne 4) {
    Write-Host "«$IP» no es una IP. Ejemplo: powershell -ExecutionPolicy Bypass -File .\quien-es.ps1 192.168.0.7"
    exit 1
}

# ───────────────────────── la ficha ─────────────────────────
Write-Host 'Investigando la IP... (unos 10 segundos)'

# 1. El ping: además de medir, obliga a Windows a averiguar la MAC (queda en la tabla de vecinos).
$sondeo = (Enviar-Pings @($IP) 2)[$IP]

# 2. La MAC sale de la tabla de vecinos (lo mismo que arp -a); el fabricante, de sus 3 primeros pares.
$datosRed = Leer-Red
$esPropia = ($IP -eq $datosRed.IP)
$dirMac = if ($esPropia) { $datosRed.MAC } else { (Leer-Vecinos $datosRed)[$IP] }
$fabricante = Obtener-Fabricante $dirMac

# 3. El nombre por DNS inverso (DNS, LLMNR o NetBIOS).
$nombreRed = (Leer-Nombres @($IP))[$IP]

# 4. Lo que el equipo anuncia por mDNS (la consulta está en RedLocal.ps1, comentada paso a paso).
$info = (Leer-Anuncios @($IP))[$IP]
$nombres = @($info.Nombres); $modelo = $info.Modelo; $marca = $info.Marca; $encontrados = $info.Servicios
$instancias = $encontrados.Count
$nombreLocal = $info.NombreRed

$sistema = if ($esPropia) { $datosRed.Sistema } elseif ($sondeo.Ttl) {
    if ($SistemaPorTtl[[int]$sondeo.Ttl]) { $SistemaPorTtl[[int]$sondeo.Ttl] } else { "poco común (TTL $($sondeo.Ttl))" } } else { '' }
$tipoAnuncio = Obtener-TipoPorAnuncio $info
$tipo = if ($esPropia) { 'Esta computadora' } elseif ($IP -eq $datosRed.Router) { 'Router' } elseif ($tipoAnuncio) { $tipoAnuncio } elseif (Probar-MacPrivada $dirMac) { 'Celular o computadora' } else { '' }

# 5. La ficha: cada dato con el lugar de donde salió.
$filas = @(
    @('Rol', $(if ($esPropia) { 'esta computadora' } elseif ($IP -eq $datosRed.Router) { 'router' } else { '' }), 'configuración de red de esta computadora'),
    @('MAC', $(if ($dirMac) { Mostrar-Mac $dirMac $MacCompleta.IsPresent } else { 'no se pudo averiguar' }), $(if ($esPropia) { 'Get-NetAdapter (la propia)' } else { "tabla de vecinos: arp -a | findstr `"$IP `"" })),
    @('Fabricante', $fabricante, $(if (Probar-MacPrivada $dirMac) { 'el segundo carácter de la MAC es 2, 6, A o E: es inventada y oculta la marca' } elseif ($dirMac) { "primeros 3 pares de la MAC ($($dirMac.Substring(0,8))) en fabricantes-mac.txt" } else { '' })),
    @('Responde', $(if ($esPropia) { '' } elseif ($sondeo.Responde) { "sí · $($sondeo.Latencia) ms" } else { 'no responde al ping (puede estar dormido o bloquearlo)' }), "ping -n 2 $IP"),
    @('Sistema', $sistema, $(if ($esPropia) { 'el sistema de esta computadora' } elseif ($sondeo.Ttl) { "el TTL de esa respuesta ($($sondeo.Ttl))" } else { '' })),
    @('Nombre', $(if ($nombres) { $nombres -join ', ' } elseif ($nombreRed) { $nombreRed } else { '?' }), $(if ($nombres) { 'lo que el equipo anuncia por mDNS' } else { "DNS inverso: nslookup $IP" })),
    @('Nombre de red', $(if ($nombreLocal) { $nombreLocal } else { '' }), 'el nombre .local de su anuncio'),
    @('Modelo', ((@($marca, $modelo) | Where-Object { $_ }) -join ' '), 'la ficha de su anuncio (md=, model=)'),
    @('Servicios', (($encontrados.Keys | ForEach-Object { "$_ :$($encontrados[$_])" }) -join ', '), 'consulta mDNS a 224.0.0.251:5353'),
    @('Tipo', $tipo, $(if ($tipo -and -not $esPropia) { 'deducido de su MAC y sus servicios' } else { '' }))
)
$ancho = ($filas | Where-Object { $_[1] } | ForEach-Object { "$($_[1])".Length } | Measure-Object -Maximum).Maximum
Write-Host ''
Write-Host "FICHA DE $IP"
foreach ($f in $filas) {
    if ($f[1]) { Write-Host ('  {0} {1}   ' -f $f[0].PadRight(14), "$($f[1])".PadRight($ancho)) -NoNewline; Write-Host $f[2] -ForegroundColor DarkGray }
}
if (-not $instancias -and -not $esPropia) {
    Write-Host ''
    Write-Host '  Este equipo no anuncia servicios. Los celulares casi nunca lo hacen y usan MAC privada, para que no los rastreen.' -ForegroundColor DarkGray
}
Write-Host ''
