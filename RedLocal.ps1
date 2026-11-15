# RedLocal.ps1 — el «motor» que usan escanear-red.ps1 y vigilar-red.ps1 (Windows).
# ====================================================================================
#
# Este archivo no se ejecuta solo: lo cargan los otros dos programas. Acá está todo el trabajo de
# averiguar qué hay en la red. Es la misma idea que hacerlo a mano en PowerShell, pero automatizada:
#
#   1. ¿Dónde estoy?            Get-NetRoute, Get-NetIPAddress  → mi IP, mi red, mi router   (Leer-Red)
#   2. ¿Con quién hablé?        Get-NetNeighbor (como arp -a)    → IP y MAC de los vecinos     (Leer-Vecinos)
#   3. (Opcional) ¿Quién más?   un ping a cada dirección de la red                            (Relevar-Red -Barrido)
#   4. ¿Responde? ¿Qué sistema? dos pings: latencia y TTL                                     (Enviar-Pings)
#   5. ¿Cómo se llama?          consulta inversa de nombre (DNS, LLMNR o NetBIOS)             (Leer-Nombres)
#   6. ¿De qué marca es?        los 3 primeros bytes de la MAC                                 (Obtener-Fabricante)
#   7. ¿Qué es y qué modelo?    lo que el equipo anuncia por mDNS (consulta propia)            (Leer-Anuncios)
#
# Nada está fijo: la interfaz, la red y el router se descubren en el momento.
# El barrido (paso 3) es descubrimiento activo: usalo solo en tu red o con autorización.
#
# Fuentes de cada dato:
#   IP y MAC ............ tabla de vecinos (Get-NetNeighbor, lo mismo que arp -a)
#   Fabricante .......... los primeros 3 bytes de la MAC, en la base de la IEEE (fabricantes-mac.txt)
#   MAC privada ......... el bit «administrada localmente» de la MAC
#   Latencia y sistema .. dos pings: el tiempo de respuesta y el TTL (64, 128 o 255)
#   Nombre .............. la consulta inversa (DNS, LLMNR o NetBIOS)
# Windows no trae una herramienta para leer los servicios que anuncian los equipos (mDNS):
# esas columnas están en la versión para Mac y Linux.

$BaseFabricantes = Join-Path $PSScriptRoot 'fabricantes-mac.txt'   # copia de https://www.wireshark.org/download/automated/data/manuf
$ArchivoInventario = Join-Path $PSScriptRoot 'inventario-activos.csv'
$ArchivoRegistro = Join-Path $PSScriptRoot 'alertas-red.log'
$MaxBarrido = 1024
$SistemaPorTtl = @{ 64 = 'Linux, Android o Apple'; 128 = 'Windows'; 255 = 'Equipo de red' }

# ───────────────────────── utilidades ─────────────────────────
function Obtener-Ahora { Get-Date -Format 'dd/MM/yyyy HH:mm' }

# Una IP es un número de 32 bits escrito en 4 partes. Para calcular la red y recorrer sus direcciones
# conviene pasarla a número: 192.168.0.1 → 3232235521. Y al revés para mostrarla.

function Convertir-IpANumero([string]$ip) {
    $bytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function Convertir-NumeroAIp([uint32]$numero) {
    $bytes = [BitConverter]::GetBytes($numero)
    [Array]::Reverse($bytes)
    return ($bytes -join '.')
}

# True si la IP puede ser de un equipo. Descarta las especiales: 224 a 239 (multicast, avisos a un grupo),
# 127.x (la propia computadora), 169.254.x (sin configuración) y las que terminan en .255 (difusión).
function Probar-IpDeEquipo([string]$ip) {
    $partes = $ip.Split('.')
    if ($partes.Count -ne 4) { return $false }
    $primero = [int]$partes[0]
    return -not (($primero -ge 224) -or $ip.EndsWith('.255') -or $ip.StartsWith('127.') -or $ip.StartsWith('169.254.'))
}

function Probar-MacPrivada([string]$dirMac) {
    # Los celulares y muchas computadoras inventan una MAC distinta para cada Wi-Fi, para que no los rastreen.
    # Esas MAC tienen encendido el bit «administrada localmente», que se ve en el segundo carácter: 2, 6, A o E.
    #   fe:7f:34:…  →  e  →  privada          94:e6:ba:…  →  4  →  de fábrica (Samsung)
    return [bool]($dirMac -and ([Convert]::ToInt32($dirMac.Substring(0, 2), 16) -band 2))
}

# Para proyectar en clase, la MAC se muestra tapada: a4:2b:b0:0c:08:60 → a4:2b:b0:xx:xx:xx
# (los 3 primeros bytes, el fabricante, quedan a la vista).
function Mostrar-Mac([string]$dirMac, [bool]$completa) {
    if ($completa -or -not $dirMac) { return $dirMac }
    return $dirMac.Substring(0, 8) + ':xx:xx:xx'
}

# ───────────────────────── datos de esta computadora y de la red ─────────────────────────
# Averigua dónde está parada esta computadora. Se puede probar a mano en PowerShell:
#   Get-NetRoute -DestinationPrefix 0.0.0.0/0    → la puerta de enlace (el router), por ejemplo 192.168.0.1
#   Get-NetIPAddress -AddressFamily IPv4          → la IP y el prefijo, por ejemplo 192.168.0.15 /24
#   Get-DnsClientServerAddress                    → los servidores DNS
#   netsh wlan show interfaces                    → la seguridad y el canal del Wi-Fi
function Leer-Red {
    $datos = [ordered]@{ Interfaz = ''; Indice = $null; IP = ''; MAC = ''; Prefijo = 24; Red = ''; Direcciones = 0
                         Router = ''; DNS = @(); WiFi = ''; Equipo = ''; Sistema = '' }
    $ruta = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    if ($ruta) {
        $datos.Router = $ruta.NextHop
        $datos.Indice = $ruta.InterfaceIndex
        $direccion = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $ruta.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1
        $adaptador = Get-NetAdapter -InterfaceIndex $ruta.InterfaceIndex -ErrorAction SilentlyContinue
        if ($direccion) { $datos.IP = $direccion.IPAddress; $datos.Prefijo = [int]$direccion.PrefixLength }
        if ($adaptador) { $datos.Interfaz = $adaptador.Name; $datos.MAC = $adaptador.MacAddress.ToLower().Replace('-', ':') }
        $datos.DNS = @((Get-DnsClientServerAddress -InterfaceIndex $ruta.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Select-Object -First 3)
    }
    if ($datos.IP) {
        $mascara = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $datos.Prefijo))
        $datos.Red = "$(Convertir-NumeroAIp ((Convertir-IpANumero $datos.IP) -band $mascara))/$($datos.Prefijo)"
        $datos.Direcciones = [int]([math]::Pow(2, 32 - $datos.Prefijo) - 2)
    }
    $sistema = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($sistema) { $datos.Equipo = "$($sistema.Manufacturer) $($sistema.Model)".Trim() }
    $datos.Sistema = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
    $wifi = netsh wlan show interfaces 2>$null
    $seguridad = ($wifi | Select-String '^\s*(Authentication|Autenticaci.n)\s*:\s*(.+)$' | Select-Object -First 1)
    $canal = ($wifi | Select-String '^\s*(Channel|Canal)\s*:\s*(\d+)' | Select-Object -First 1)
    if ($seguridad) {
        $datos.WiFi = $seguridad.Matches[0].Groups[2].Value.Trim()
        if ($canal) { $datos.WiFi += " · canal $($canal.Matches[0].Groups[2].Value)" }
    }
    return [PSCustomObject]$datos
}

function Obtener-DireccionesABarrer($datosRed) {
    # Las direcciones de la red local. Si la red es muy grande, solo las 254 vecinas a esta computadora.
    if (-not $datosRed.IP) { return @() }
    $prefijo = if ($datosRed.Direcciones + 2 -le $MaxBarrido) { $datosRed.Prefijo } else { 24 }
    $mascara = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $prefijo))
    $base = (Convertir-IpANumero $datosRed.IP) -band $mascara
    $total = [uint32][math]::Pow(2, 32 - $prefijo)
    $lista = for ($i = [uint32]1; $i -lt $total - 1; $i++) { Convertir-NumeroAIp ([uint32]($base + $i)) }
    return @($lista | Where-Object { $_ -ne $datosRed.IP })
}

function Enviar-Pings([string[]]$ips, [int]$veces) {
    # Envía los pings en paralelo y devuelve, por IP, la mejor respuesta: @{ Responde; Latencia; Ttl }.
    # - Latencia: cuánto tarda en ir y volver (en una red de casa, pocos milisegundos).
    # - TTL: un número que pone cada sistema en sus paquetes. En la red local llega el valor original:
    #   64 sugiere Linux, Android o Apple; 128, Windows; 255, un equipo de red. Es una pista, no una prueba.
    # Se envían dos pings porque el primero muchas veces se pierde mientras el equipo se despierta.
    # Un celular bloqueado suele no contestar: «no responde» no significa «no está».
    $tareas = foreach ($ip in $ips) {
        for ($n = 0; $n -lt $veces; $n++) {
            @{ IP = $ip; Tarea = (New-Object System.Net.NetworkInformation.Ping).SendPingAsync($ip, 1500) }
        }
    }
    $resultado = @{}
    foreach ($ip in $ips) { $resultado[$ip] = @{ Responde = $false; Latencia = $null; Ttl = $null } }
    foreach ($t in $tareas) {
        try {
            $respuesta = $t.Tarea.Result
            if ($respuesta.Status -eq 'Success') {
                $actual = $resultado[$t.IP]
                if (-not $actual.Responde -or $respuesta.RoundtripTime -lt $actual.Latencia) {
                    $ttl = if ($respuesta.Options) { $respuesta.Options.Ttl } else { $null }
                    $resultado[$t.IP] = @{ Responde = $true; Latencia = $respuesta.RoundtripTime; Ttl = $ttl }
                }
            }
        } catch { }
    }
    return $resultado
}

function Leer-Vecinos($datosRed) {
    # La tabla de vecinos (lo mismo que muestra «arp -a»): IP y MAC de los equipos con los que esta
    # computadora habló hace poco. Cuando quiere hablar con otro equipo, pregunta a toda la red
    # «¿quién tiene la 192.168.0.7?» y el dueño contesta con su MAC. La respuesta queda anotada un rato.
    $vecinos = @{}
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.State -notin @('Unreachable', 'Incomplete') -and $_.LinkLayerAddress -and
        $_.LinkLayerAddress -notin @('00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF') -and (Probar-IpDeEquipo $_.IPAddress) -and
        (-not $datosRed.Indice -or $_.InterfaceIndex -eq $datosRed.Indice)
    } | ForEach-Object { $vecinos[$_.IPAddress] = $_.LinkLayerAddress.ToLower().Replace('-', ':') }
    return $vecinos
}

# El nombre de cada IP («DNS inverso»): de 192.168.0.7 a «Living-TV». Windows lo busca en el DNS,
# y si no, preguntándole a la red por LLMNR o NetBIOS. Muchos equipos no contestan: queda «?».
function Leer-Nombres([string[]]$ips) {
    $tareas = foreach ($ip in $ips) { @{ IP = $ip; Tarea = [System.Net.Dns]::GetHostEntryAsync($ip) } }
    $nombres = @{}
    foreach ($t in $tareas) {
        try { if ($t.Tarea.Wait(2500) -and $t.Tarea.Result.HostName -ne $t.IP) { $nombres[$t.IP] = $t.Tarea.Result.HostName } } catch { }
    }
    return $nombres
}

# ───────────────────────── fabricantes ─────────────────────────
# Cada fabricante de placas de red compra a la IEEE un bloque de direcciones: los 3 primeros bytes de la MAC
# dicen quién fabricó la placa. Renglón de ejemplo de fabricantes-mac.txt:
#   94:E6:BA    SamsungElect    Samsung Electronics Co.,Ltd
# Ojo: es el fabricante de la PLACA, no siempre la marca del aparato.
$script:Fabricantes = $null
function Obtener-Fabricante([string]$dirMac) {
    if (-not $dirMac) { return '' }
    if (Probar-MacPrivada $dirMac) { return 'privada' }
    if ($null -eq $script:Fabricantes) {
        $script:Fabricantes = @{}
        if (Test-Path $BaseFabricantes) {
            foreach ($linea in [System.IO.File]::ReadLines($BaseFabricantes)) {
                $partes = $linea.Split("`t")
                if ($partes.Count -gt 1 -and $partes[0].Trim().Length -eq 8) { $script:Fabricantes[$partes[0].Trim().ToLower()] = $partes[-1].Trim() }
            }
        }
    }
    $nombre = $script:Fabricantes[$dirMac.Substring(0, 8)]
    if (-not $nombre) { return 'desconocido' }
    return ($nombre -replace '[,\s]+(Co\.?|Ltd\.?|Inc\.?|Corp\.?|Corporation|Technologies|Technology|Electronics|International)\b.*$', '').Trim(' ,')
}

# ───────────────────────── anuncios de los equipos (mDNS) ─────────────────────────
# En Mac existe el comando dns-sd y en Linux avahi-browse, que escuchan lo que los equipos anuncian
# de sí mismos (mDNS, el «DNS multicast»). Windows no trae ninguno, así que acá se hace a mano.

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
    '_matter._tcp'          = @('Matter', 'Domótica')
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
# Además se pregunta directo a cada IP: el firewall de Windows deja pasar la respuesta de un equipo
# al que se le preguntó, y así no se pierden respuestas.
function Escuchar-Anuncios([string[]]$ips, [int]$segundos = 4) {
    $udp = New-Object System.Net.Sockets.UdpClient(0)
    $udp.Client.ReceiveTimeout = 400
    $multicast = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('224.0.0.251'), 5353)
    $consultas = @($Servicios.Keys | ForEach-Object { , (Nuevo-Consulta @("$_.local") 12) })
    foreach ($ip in $ips) {                                  # «¿quién es la 192.168.0.7?» (DNS inverso por mDNS)
        $partes = $ip.Split('.'); [Array]::Reverse($partes)
        $consultas += , (Nuevo-Consulta @((($partes -join '.') + '.in-addr.arpa')) 12)
    }
    $registros = @()
    for ($vuelta = 0; $vuelta -lt 2; $vuelta++) {           # dos vueltas: algunos equipos no contestan la primera
        foreach ($c in $consultas) {
            [void]$udp.Send($c, $c.Length, $multicast)
            foreach ($ip in $ips) { [void]$udp.Send($c, $c.Length, (New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ip), 5353))) }
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

# Ordena lo que se escuchó por IP: nombre, marca, modelo, servicios (con su puerto) y clase de equipo.
function Leer-Anuncios([string[]]$ips) {
    $resultado = @{}
    if (-not $ips) { return $resultado }
    $registros = @(Escuchar-Anuncios $ips)
    foreach ($ip in $ips) {
        $locales = @($registros | Where-Object { $_.Tipo -eq 1 -and $_.Valor -eq $ip } | ForEach-Object { $_.Nombre })
        $partes = $ip.Split('.'); [Array]::Reverse($partes); $inverso = ($partes -join '.') + '.in-addr.arpa'
        $locales += @($registros | Where-Object { $_.Tipo -eq 12 -and $_.Nombre -eq $inverso } | ForEach-Object { $_.Valor })
        $instancias = @($registros | Where-Object { $_.Tipo -eq 33 -and ($_.Origen -eq $ip -or $locales -contains $_.Valor.Destino) })
        $info = @{ Nombres = @(); Marca = ''; Modelo = ''; Servicios = [ordered]@{}; Clases = @(); NombreRed = '' }
        foreach ($inst in $instancias) {
            $tipoServicio = ($Servicios.Keys | Where-Object { $inst.Nombre -like "*.$_.local" } | Select-Object -First 1)
            if ($tipoServicio) { $info.Servicios[$Servicios[$tipoServicio][0]] = $inst.Valor.Puerto; $info.Clases += $Servicios[$tipoServicio][1] }
            $locales += $inst.Valor.Destino
            $txt = ($registros | Where-Object { $_.Tipo -eq 16 -and $_.Nombre -eq $inst.Nombre } | Select-Object -First 1).Valor
            $legible = if ($txt -and $txt['fn']) { $txt['fn'] } else { ($inst.Nombre -split '\._')[0] }
            if ($legible -match '@') { $legible = $legible.Split('@')[-1] }            # AirPlay audio: «MAC@nombre»
            if ($legible -match '^[0-9a-fA-F-]{16,}$') { $legible = '' }             # identificadores sin nombre legible
            if ($legible -and $info.Nombres -notcontains $legible) { $info.Nombres += $legible }
            if ($txt) {
                if (-not $info.Modelo) { $info.Modelo = @($txt['md'], $txt['model'], $txt['ty'], $txt['usb_mdl']) | Where-Object { $_ } | Select-Object -First 1 }
                if (-not $info.Marca) { $info.Marca = @($txt['manufacturer'], $txt['usb_mfg']) | Where-Object { $_ } | Select-Object -First 1 }
            }
        }
        $info.NombreRed = ($locales | Where-Object { $_ } | Select-Object -First 1)
        $resultado[$ip] = $info
    }
    return $resultado
}

# Equipos inteligentes que casi nunca anuncian nada: se reconocen por el fabricante de su placa de red.
$TipoPorFabricante = [ordered]@{ 'wiz' = 'Lámpara inteligente'; 'signify' = 'Lámpara inteligente'; 'philips lighting' = 'Lámpara inteligente'
    'tuya' = 'Dispositivo inteligente'; 'espressif' = 'Dispositivo inteligente'; 'hikvision' = 'Cámara'; 'dahua' = 'Cámara'; 'ezviz' = 'Cámara'; 'ring' = 'Cámara o timbre' }
function Obtener-TipoPorFabricante([string]$dirMac) {
    $fabricante = (Obtener-Fabricante $dirMac).ToLower()
    foreach ($marca in $TipoPorFabricante.Keys) { if ($fabricante.Contains($marca)) { return $TipoPorFabricante[$marca] } }
    return ''
}

# El tipo de equipo, deducido de su modelo y de los servicios que anuncia.
function Obtener-TipoPorAnuncio($info) {
    if (-not $info) { return '' }
    switch -Regex ($info.Modelo) {
        '^(Mac|MacBook|iMac)' { return 'Computadora (Mac)' }
        '^iPhone' { return 'Celular (iPhone)' }
        '^iPad' { return 'Tablet (iPad)' }
        '^AppleTV' { return 'TV o reproductor' }
    }
    $clases = @($info.Clases | Where-Object { $_ })
    if ($clases.Count) { return ($clases | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name }
    return ''
}

# ───────────────────────── relevamiento ─────────────────────────
# Hace todos los pasos y devuelve la red y la lista de equipos ordenada por IP.
# Con -Barrido, primero saluda a todas las direcciones de la red: no importa si contestan el ping,
# para enviarlo Windows tiene que preguntar la MAC, y cada equipo encendido contesta esa pregunta.
# Desde el lado del defensor, un equipo que pregunta por todas las direcciones en pocos segundos
# es un comportamiento típico de descubrimiento de la red, y muchos sistemas de detección lo marcan.
function Relevar-Red([bool]$barrido) {
    $datosRed = Leer-Red
    if ($barrido) { [void](Enviar-Pings (Obtener-DireccionesABarrer $datosRed) 1) }   # deja a los equipos encendidos en la tabla de vecinos
    $vecinos = Leer-Vecinos $datosRed
    $vecinos.Remove($datosRed.IP)
    # Si una misma MAC responde por muchas IP (proxy ARP, típico de redes en la nube), se deja una sola.
    $proxy = 0
    foreach ($grupo in @($vecinos.GetEnumerator() | Group-Object Value | Where-Object { $_.Count -ge 4 })) {
        $ipsDelGrupo = @($grupo.Group | ForEach-Object { $_.Key })
        $conservar = if ($datosRed.Router -in $ipsDelGrupo) { $datosRed.Router } else { $ipsDelGrupo | Sort-Object { [version]$_ } | Select-Object -First 1 }
        foreach ($ip in $ipsDelGrupo) { if ($ip -ne $conservar) { $vecinos.Remove($ip); $proxy++ } }
    }
    $datosRed | Add-Member -NotePropertyName Proxy -NotePropertyValue $proxy -Force
    $ips = @($vecinos.Keys)
    $sondeos = if ($ips.Count) { Enviar-Pings $ips 2 } else { @{} }
    $nombres = if ($ips.Count) { Leer-Nombres $ips } else { @{} }
    $anuncios = if ($ips.Count) { Leer-Anuncios $ips } else { @{} }   # lo que cada equipo anuncia: nombre, modelo y servicios

    $equipos = foreach ($ip in $ips) {
        $dirMac = $vecinos[$ip]
        $sondeo = $sondeos[$ip]
        $info = $anuncios[$ip]
        $tipoAnuncio = Obtener-TipoPorAnuncio $info
        $tipoMarca = Obtener-TipoPorFabricante $dirMac
        $tipo = if ($ip -eq $datosRed.Router) { 'Router' } elseif ($tipoAnuncio) { $tipoAnuncio } elseif ($tipoMarca) { $tipoMarca } elseif (Probar-MacPrivada $dirMac) { 'Celular o computadora' } else { '' }
        $nombre = if ($info -and $info.Nombres) { $info.Nombres[0] } else { "$($nombres[$ip])" }
        $modelo = if ($info) { ((@($info.Marca, $info.Modelo) | Where-Object { $_ }) -join ' ') } else { '' }
        $servicios = if ($info) { ($info.Servicios.Keys | ForEach-Object { "$_ :$($info.Servicios[$_])" }) -join ', ' } else { '' }
        $sistema = if ($sondeo.Ttl) { if ($SistemaPorTtl[[int]$sondeo.Ttl]) { $SistemaPorTtl[[int]$sondeo.Ttl] } else { "poco común (TTL $($sondeo.Ttl))" } } else { '' }
        [PSCustomObject]@{ IP = $ip; MAC = $dirMac; Nombre = $nombre; Tipo = $tipo; Modelo = $modelo; Sistema = $sistema
                           Responde = $sondeo.Responde; Latencia = $sondeo.Latencia; Clave = $dirMac; Servicios = $servicios }
    }
    $equipos = @($equipos)
    if ($datosRed.IP) {
        $equipos += [PSCustomObject]@{ IP = $datosRed.IP; MAC = $datosRed.MAC; Nombre = $env:COMPUTERNAME; Tipo = 'Esta computadora'
                                       Modelo = $datosRed.Equipo; Sistema = $datosRed.Sistema; Responde = $true; Latencia = $null; Clave = $datosRed.MAC; Servicios = '' }
    }
    return [PSCustomObject]@{ Red = $datosRed; Equipos = @($equipos | Sort-Object { [version]$_.IP }) }
}

# ───────────────────────── presentación ─────────────────────────
function Convertir-AFila($equipo, [bool]$macCompleta) {
    # Un equipo como fila de tabla. Cada dato aparece una sola vez.
    $nombre = $equipo.Nombre
    if ($nombre.Length -gt 28) { $nombre = $nombre.Substring(0, 27) + '…' }
    $latencia = if ($equipo.Tipo -eq 'Esta computadora') { '' } elseif ($equipo.Responde) { "$($equipo.Latencia) ms" } else { 'no responde' }
    return [PSCustomObject][ordered]@{
        IP = $equipo.IP; MAC = (Mostrar-Mac $equipo.MAC $macCompleta); Fabricante = (Obtener-Fabricante $equipo.MAC)
        Nombre = $nombre; Tipo = $equipo.Tipo; Modelo = $equipo.Modelo; Sistema = $equipo.Sistema; Latencia = $latencia
        Servicios = $equipo.Servicios
    }
}

function Imprimir-Tabla($filas, [string]$color) {
    # Imprime una lista de objetos como tabla. Las columnas vacías no se muestran.
    $filas = @($filas)
    if (-not $filas.Count) { return }
    $columnas = @($filas[0].PSObject.Properties.Name | Where-Object { $columna = $_; @($filas | Where-Object { "$($_.$columna)" }).Count -gt 0 })
    $anchos = @{}
    foreach ($columna in $columnas) {
        $anchos[$columna] = (@($columna.Length) + @($filas | ForEach-Object { "$($_.$columna)".Length }) | Measure-Object -Maximum).Maximum
    }
    Write-Host ((($columnas | ForEach-Object { $_.PadRight($anchos[$_]) }) -join '  ').TrimEnd())
    Write-Host (($columnas | ForEach-Object { '-' * $anchos[$_] }) -join '  ') -ForegroundColor DarkGray
    foreach ($fila in $filas) {
        $linea = (($columnas | ForEach-Object { "$($fila.$_)".PadRight($anchos[$_]) }) -join '  ').TrimEnd()
        if ($color) { Write-Host $linea -ForegroundColor $color } else { Write-Host $linea }
    }
}

function Mostrar-Encabezado([string]$titulo, $datosRed, [string]$metodo) {
    Write-Host "`n$titulo · $(Obtener-Ahora)" -ForegroundColor White
    $lineas = [ordered]@{
        'Esta computadora' = (@($datosRed.Equipo, $datosRed.Sistema, $datosRed.IP, $datosRed.Interfaz) | Where-Object { $_ }) -join ' · '
        'Red'              = $(if ($datosRed.Red) { "$($datosRed.Red) · $($datosRed.Direcciones) direcciones posibles" } else { 'sin conexión' })
        'Router'           = $datosRed.Router
        'DNS en uso'       = $datosRed.DNS -join ', '
        'Wi-Fi'            = $datosRed.WiFi
        'Método'           = $metodo
        'Aviso'            = $(if ($datosRed.Proxy) { "una misma MAC responde por $($datosRed.Proxy + 1) direcciones (proxy ARP): se cuenta como un solo equipo" } else { '' })
    }
    $trafico = Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $datosRed.Interfaz }
    if ($trafico) {
        $legible = { param($b) if ($b -ge 1GB) { '{0:N1} GB' -f ($b / 1GB) } else { '{0:N0} MB' -f ($b / 1MB) } }
        $lineas['Tráfico propio'] = "recibido $(& $legible $trafico.ReceivedBytes) · enviado $(& $legible $trafico.SentBytes) desde el encendido"
    }
    foreach ($etiqueta in $lineas.Keys) {
        if ($lineas[$etiqueta]) {
            Write-Host "  $($etiqueta.PadRight(17)) " -ForegroundColor DarkGray -NoNewline
            Write-Host $lineas[$etiqueta]
        }
    }
    Write-Host ''
}

function Obtener-Metodo([bool]$barrido, $datosRed) {
    if ($barrido) { return "activo: barrido de $(@(Obtener-DireccionesABarrer $datosRed).Count) direcciones + tabla de vecinos" }
    return 'pasivo: tabla de vecinos (con -Barrido se saluda a toda la red)'
}

# ───────────────────────── inventario de activos ─────────────────────────
# ───────── El inventario es la lista oficial de lo que DEBERÍA estar en la red (CIS Control 1) ─────────
# Se guarda en inventario-activos.csv, que se abre con Excel. «Autorizado» y «Responsable» las completa
# una persona: el programa nunca las pisa.
function Leer-Inventario {
    # El inventario guardado, por clave. La clave es la MAC.
    $inventario = [ordered]@{}
    if (Test-Path $ArchivoInventario) {
        foreach ($fila in (Import-Csv $ArchivoInventario -Encoding UTF8)) {
            $clave = if ($fila.MAC) { $fila.MAC } else { "ip:$($fila.IP)" }
            $inventario[$clave] = $fila
        }
    }
    return $inventario
}

function Guardar-Inventario($inventario) {
    @($inventario.Values) | Sort-Object { if (Probar-IpDeEquipo $_.IP) { [version]$_.IP } else { [version]'0.0.0.0' } } |
        Export-Csv $ArchivoInventario -NoTypeInformation -Encoding UTF8
}

function Probar-Autorizado($fila) {
    return "$($fila.Autorizado)".Trim().ToLower() -in @('sí', 'si')
}

function Registrar-Equipos($inventario, $equipos) {
    # Suma al inventario los equipos relevados, sin tocar lo que cargó una persona. Devuelve las claves nuevas.
    $nuevas = @()
    foreach ($e in $equipos) {
        $anterior = $inventario[$e.Clave]
        if (-not $anterior) {
            $nuevas += $e.Clave
            $anterior = [PSCustomObject]@{ Nombre = ''; Tipo = ''; Modelo = ''; Sistema = ''; Servicios = ''; Responsable = ''
                                           'Primera vez' = (Obtener-Ahora); Autorizado = $(if ($e.Tipo -eq 'Esta computadora') { 'sí' } else { 'pendiente' }) }
        }
        # «Celular o computadora» sale solo de la MAC privada: no pisa un tipo mejor que ya se conocía.
        $tipo = if ((-not $e.Tipo -or $e.Tipo -eq 'Celular o computadora') -and $anterior.Tipo) { $anterior.Tipo } else { $e.Tipo }
        $inventario[$e.Clave] = [PSCustomObject][ordered]@{
            'MAC'         = $e.MAC
            'IP'          = $e.IP
            'Nombre'      = $(if ($e.Nombre) { $e.Nombre } else { $anterior.Nombre })
            'Fabricante'  = Obtener-Fabricante $e.MAC
            'Tipo'        = $tipo
            'Modelo'      = $(if ($e.Modelo) { $e.Modelo } else { $anterior.Modelo })
            'Sistema'     = $(if ($e.Sistema) { $e.Sistema } else { $anterior.Sistema })
            'Servicios'   = $anterior.Servicios
            'Primera vez' = $anterior.'Primera vez'
            'Última vez'  = Obtener-Ahora
            'Autorizado'  = $anterior.Autorizado
            'Responsable' = $anterior.Responsable
        }
    }
    return , $nuevas
}
