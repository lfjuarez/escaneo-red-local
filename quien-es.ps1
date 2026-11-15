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

# Los tipos de servicio que más se ven en una red de casa u oficina, con un nombre en castellano
# y la clase de equipo que suelen indicar.
$Servicios = [ordered]@{
    '_googlecast._tcp'      = @('Chromecast', 'TV o reproductor')
    '_airplay._tcp'         = @('AirPlay', 'TV o reproductor')
    '_raop._tcp'            = @('AirPlay audio', 'Parlante')
    '_spotify-connect._tcp' = @('Spotify Connect', 'Parlante')
    '_ipp._tcp'             = @('Impresión', 'Impresora')
    '_printer._tcp'         = @('Impresión', 'Impresora')
    '_pdl-datastream._tcp'  = @('Impresión', 'Impresora')
    '_scanner._tcp'         = @('Escáner', 'Impresora')
    '_hap._tcp'             = @('HomeKit', 'Domótica')
    '_companion-link._tcp'  = @('Apple', 'Equipo de Apple')
    '_smb._tcp'             = @('Archivos SMB', 'Computadora')
    '_ssh._tcp'             = @('SSH', 'Computadora')
    '_http._tcp'            = @('Web', '')
}

# ───────────────────────── mDNS hecho a mano ─────────────────────────
# Un mensaje DNS tiene un encabezado de 12 bytes y después las preguntas. Cada nombre se escribe por
# partes: «_googlecast._tcp.local» → 11 _googlecast 4 _tcp 5 local 0.
function Nuevo-Consulta([string[]]$nombres, [int]$tipo) {
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.AddRange([byte[]](0, 0, 0, 0, 0, [byte]$nombres.Count, 0, 0, 0, 0, 0, 0))
    foreach ($nombre in $nombres) {
        foreach ($parte in $nombre.Split('.')) {
            $b = [Text.Encoding]::UTF8.GetBytes($parte); $bytes.Add([byte]$b.Length); $bytes.AddRange($b)
        }
        $bytes.Add(0)
        $bytes.AddRange([byte[]](0, [byte]$tipo, 0x80, 1))   # tipo; clase IN con el bit «respondeme a mí» (QU)
    }
    return $bytes.ToArray()
}

# Lee un nombre dentro de una respuesta. Los nombres pueden estar «comprimidos»: en vez de repetirlos,
# la respuesta apunta a donde ya aparecieron (dos bytes que empiezan con 11 en binario).
function Leer-NombreDns([byte[]]$d, [int]$pos) {
    $partes = @(); $saltos = 0; $fin = -1
    while ($pos -lt $d.Length) {
        $largo = $d[$pos]
        if ($largo -eq 0) { $pos++; break }
        if (($largo -band 0xC0) -eq 0xC0) {
            if ($fin -lt 0) { $fin = $pos + 2 }
            $pos = (($largo -band 0x3F) -shl 8) + $d[$pos + 1]; $saltos++
            if ($saltos -gt 20) { break }
            continue
        }
        $partes += [Text.Encoding]::UTF8.GetString($d, $pos + 1, $largo); $pos += $largo + 1
    }
    if ($fin -lt 0) { $fin = $pos }
    return @(($partes -join '.'), $fin)
}

# Lee todos los registros de una respuesta: PTR (qué instancias hay), SRV (nombre de red y puerto),
# TXT (la ficha: fn=, md=, model=…) y A (la IP del nombre .local).
function Leer-Registros([byte[]]$d) {
    $registros = @()
    try {
        $preguntas = $d[4] * 256 + $d[5]
        $total = ($d[6] * 256 + $d[7]) + ($d[8] * 256 + $d[9]) + ($d[10] * 256 + $d[11])
        $pos = 12
        for ($i = 0; $i -lt $preguntas; $i++) { $pos = (Leer-NombreDns $d $pos)[1] + 4 }
        for ($i = 0; $i -lt $total; $i++) {
            $r = Leer-NombreDns $d $pos; $nombre = $r[0]; $pos = $r[1]
            $tipo = $d[$pos] * 256 + $d[$pos + 1]; $largo = $d[$pos + 8] * 256 + $d[$pos + 9]; $datos = $pos + 10
            $valor = $null
            switch ($tipo) {
                1  { $valor = '{0}.{1}.{2}.{3}' -f $d[$datos], $d[$datos + 1], $d[$datos + 2], $d[$datos + 3] }
                12 { $valor = (Leer-NombreDns $d $datos)[0] }
                33 { $valor = @{ Puerto = $d[$datos + 4] * 256 + $d[$datos + 5]; Destino = (Leer-NombreDns $d ($datos + 6))[0] } }
                16 {
                    $txt = @{}; $p = $datos
                    while ($p -lt $datos + $largo) {
                        $l = $d[$p]; if ($l -gt 0) {
                            $par = [Text.Encoding]::UTF8.GetString($d, $p + 1, $l); $k = $par.IndexOf('=')
                            if ($k -gt 0) { $txt[$par.Substring(0, $k).ToLower()] = $par.Substring($k + 1) }
                        }
                        $p += $l + 1
                    }
                    $valor = $txt
                }
            }
            $registros += [PSCustomObject]@{ Nombre = $nombre; Tipo = $tipo; Valor = $valor }
            $pos = $datos + $largo
        }
    } catch { }
    return $registros
}

# Envía las preguntas a 224.0.0.251:5353 y junta todas las respuestas durante unos segundos.
# Como el pedido sale desde un puerto que no es el 5353, los equipos contestan directo a esta computadora.
function Escuchar-Anuncios([string]$ipBuscada, [int]$segundos = 4) {
    $partes = $ipBuscada.Split('.'); [Array]::Reverse($partes)
    $inverso = ($partes -join '.') + '.in-addr.arpa'
    $udp = New-Object System.Net.Sockets.UdpClient(0)
    $udp.Client.ReceiveTimeout = 500
    $destino = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('224.0.0.251'), 5353)
    $directo = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ipBuscada), 5353)
    $consultas = @((Nuevo-Consulta @($inverso) 12)) + @($Servicios.Keys | ForEach-Object { , (Nuevo-Consulta @("$_.local") 12) })
    $registros = @()
    for ($vuelta = 0; $vuelta -lt 2; $vuelta++) {           # dos vueltas: algunos equipos no contestan la primera
        foreach ($c in $consultas) {
            [void]$udp.Send($c, $c.Length, $destino)      # a toda la red (multicast)
            [void]$udp.Send($c, $c.Length, $directo)      # y directo al equipo: el firewall de Windows deja pasar su respuesta
        }
        $limite = (Get-Date).AddSeconds($segundos / 2)
        while ((Get-Date) -lt $limite) {
            try {
                $origen = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $datos = $udp.Receive([ref]$origen)
                $registros += Leer-Registros $datos | ForEach-Object { $_ | Add-Member -NotePropertyName Origen -NotePropertyValue $origen.Address.ToString() -PassThru }
            } catch { }
        }
    }
    $udp.Close()
    return $registros
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

# 4. Lo que el equipo anuncia por mDNS: solo los registros que vienen de esa IP o que apuntan a ella.
$registros = Escuchar-Anuncios $IP
$nombresLocales = @($registros | Where-Object { $_.Tipo -eq 1 -and $_.Valor -eq $IP } | ForEach-Object { $_.Nombre })
$nombresLocales += @($registros | Where-Object { $_.Tipo -eq 12 -and $_.Nombre -like '*.in-addr.arpa' } | ForEach-Object { $_.Valor })
$instancias = @($registros | Where-Object { $_.Tipo -eq 33 -and ($_.Origen -eq $IP -or $nombresLocales -contains $_.Valor.Destino) })

$encontrados = [ordered]@{}; $clases = @(); $nombres = @(); $modelo = ''; $marca = ''
foreach ($inst in $instancias) {
    $tipoServicio = ($Servicios.Keys | Where-Object { $inst.Nombre -like "*.$_.local" } | Select-Object -First 1)
    if ($tipoServicio) { $encontrados[$Servicios[$tipoServicio][0]] = $inst.Valor.Puerto; $clases += $Servicios[$tipoServicio][1] }
    $nombresLocales += $inst.Valor.Destino
    $txt = ($registros | Where-Object { $_.Tipo -eq 16 -and $_.Nombre -eq $inst.Nombre } | Select-Object -First 1).Valor
    $legible = if ($txt -and $txt['fn']) { $txt['fn'] } else { ($inst.Nombre -split '\._')[0] }
    if ($legible -match '@') { $legible = $legible.Split('@')[-1] }            # AirPlay audio: «MAC@nombre»
    if ($legible -match '^[0-9a-fA-F-]{16,}$') { $legible = '' }             # identificadores sin nombre legible
    if ($legible -and $nombres -notcontains $legible) { $nombres += $legible }
    if ($txt) {
        if (-not $modelo) { $modelo = @($txt['md'], $txt['model'], $txt['ty'], $txt['usb_mdl']) | Where-Object { $_ } | Select-Object -First 1 }
        if (-not $marca) { $marca = @($txt['manufacturer'], $txt['usb_mfg']) | Where-Object { $_ } | Select-Object -First 1 }
    }
}
$nombreLocal = ($nombresLocales | Where-Object { $_ } | Select-Object -First 1)

$sistema = if ($esPropia) { $datosRed.Sistema } elseif ($sondeo.Ttl) {
    if ($SistemaPorTtl[[int]$sondeo.Ttl]) { $SistemaPorTtl[[int]$sondeo.Ttl] } else { "poco común (TTL $($sondeo.Ttl))" } } else { '' }
$tipo = if ($esPropia) { 'Esta computadora' } elseif ($IP -eq $datosRed.Router) { 'Router' } elseif ($clases | Where-Object { $_ }) {
    ($clases | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name } elseif (Probar-MacPrivada $dirMac) { 'Celular o computadora' } else { '' }

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
