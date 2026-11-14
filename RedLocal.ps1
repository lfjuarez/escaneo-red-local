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
    # Manda los pings en paralelo y devuelve, por IP, la mejor respuesta: @{ Responde; Latencia; Ttl }.
    # - Latencia: cuánto tarda en ir y volver (en una red de casa, pocos milisegundos).
    # - TTL: un número que pone cada sistema en sus paquetes. En la red local llega el valor original:
    #   64 sugiere Linux, Android o Apple; 128, Windows; 255, un equipo de red. Es una pista, no una prueba.
    # Se mandan dos pings porque el primero muchas veces se pierde mientras el equipo se despierta.
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

# ───────────────────────── relevamiento ─────────────────────────
# Hace todos los pasos y devuelve la red y la lista de equipos ordenada por IP.
# Con -Barrido, primero saluda a todas las direcciones de la red: no importa si contestan el ping,
# para mandarlo Windows tiene que preguntar la MAC, y cada equipo encendido contesta esa pregunta.
# Desde el lado del defensor, un equipo que pregunta por todas las direcciones en pocos segundos
# es un comportamiento típico de reconocimiento, y muchos sistemas de detección lo marcan.
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

    $equipos = foreach ($ip in $ips) {
        $dirMac = $vecinos[$ip]
        $sondeo = $sondeos[$ip]
        $tipo = if ($ip -eq $datosRed.Router) { 'Router' } elseif (Probar-MacPrivada $dirMac) { 'Celular o compu' } else { '' }
        $sistema = if ($sondeo.Ttl) { if ($SistemaPorTtl[[int]$sondeo.Ttl]) { $SistemaPorTtl[[int]$sondeo.Ttl] } else { "poco común (TTL $($sondeo.Ttl))" } } else { '' }
        [PSCustomObject]@{ IP = $ip; MAC = $dirMac; Nombre = "$($nombres[$ip])"; Tipo = $tipo; Modelo = ''; Sistema = $sistema
                           Responde = $sondeo.Responde; Latencia = $sondeo.Latencia; Clave = $dirMac }
    }
    $equipos = @($equipos)
    if ($datosRed.IP) {
        $equipos += [PSCustomObject]@{ IP = $datosRed.IP; MAC = $datosRed.MAC; Nombre = $env:COMPUTERNAME; Tipo = 'Esta computadora'
                                       Modelo = $datosRed.Equipo; Sistema = $datosRed.Sistema; Responde = $true; Latencia = $null; Clave = $datosRed.MAC }
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
        # «Celular o compu» sale solo de la MAC privada: no pisa un tipo mejor que ya se conocía.
        $tipo = if ((-not $e.Tipo -or $e.Tipo -eq 'Celular o compu') -and $anterior.Tipo) { $anterior.Tipo } else { $e.Tipo }
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
