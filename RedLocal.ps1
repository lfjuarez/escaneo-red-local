# Motor compartido de escanear-red.ps1 y vigilar-red.ps1 (Windows).
#
# Releva la red local con lo que trae Windows y devuelve una lista de equipos.
# Nada está fijo: la interfaz, la red y el router se descubren en el momento.
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

function Probar-IpDeEquipo([string]$ip) {
    $partes = $ip.Split('.')
    if ($partes.Count -ne 4) { return $false }
    $primero = [int]$partes[0]
    return -not (($primero -ge 224) -or $ip.EndsWith('.255') -or $ip.StartsWith('127.') -or $ip.StartsWith('169.254.'))
}

function Probar-MacPrivada([string]$dirMac) {
    # El bit «administrada localmente»: la MAC no es la de fábrica (celulares y compus que la ocultan).
    return [bool]($dirMac -and ([Convert]::ToInt32($dirMac.Substring(0, 2), 16) -band 2))
}

function Mostrar-Mac([string]$dirMac, [bool]$completa) {
    if ($completa -or -not $dirMac) { return $dirMac }
    return $dirMac.Substring(0, 8) + ':xx:xx:xx'
}

# ───────────────────────── datos de esta computadora y de la red ─────────────────────────
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
    # La tabla de vecinos: IP y MAC de los equipos con los que esta computadora habló hace poco.
    $vecinos = @{}
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.State -notin @('Unreachable', 'Incomplete') -and $_.LinkLayerAddress -and
        $_.LinkLayerAddress -notin @('00-00-00-00-00-00', 'FF-FF-FF-FF-FF-FF') -and (Probar-IpDeEquipo $_.IPAddress) -and
        (-not $datosRed.Indice -or $_.InterfaceIndex -eq $datosRed.Indice)
    } | ForEach-Object { $vecinos[$_.IPAddress] = $_.LinkLayerAddress.ToLower().Replace('-', ':') }
    return $vecinos
}

function Leer-Nombres([string[]]$ips) {
    $tareas = foreach ($ip in $ips) { @{ IP = $ip; Tarea = [System.Net.Dns]::GetHostEntryAsync($ip) } }
    $nombres = @{}
    foreach ($t in $tareas) {
        try { if ($t.Tarea.Wait(2500) -and $t.Tarea.Result.HostName -ne $t.IP) { $nombres[$t.IP] = $t.Tarea.Result.HostName } } catch { }
    }
    return $nombres
}

# ───────────────────────── fabricantes ─────────────────────────
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
