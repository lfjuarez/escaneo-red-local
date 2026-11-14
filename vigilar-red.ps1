# Vigilancia de la red local contra el inventario de activos (Windows).
#
# Compara lo que hay conectado ahora con inventario-activos.csv (lo crea escanear-red.ps1) y avisa:
#   ALERTA    un equipo que no está en el inventario o que no está autorizado
#   ALERTA    señales de ARP spoofing: la MAC del router cambió, o un equipo usa la misma MAC que el router
#   CAMBIO    un equipo autorizado cambió de IP
#   AUSENTE   un equipo autorizado que ahora no se ve
# Las alertas también se guardan en alertas-red.log, como las recibiría un SIEM.
# Termina con código 2 si hubo alertas, para poder usarlo en una tarea programada.
#
# Usalo solo en tu red o con autorización.
#
# Desde PowerShell, en la carpeta de los archivos:
#   powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1                una revisión pasiva (tabla de vecinos)
#   powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1 -Barrido       además saluda a todas las direcciones de la red (activo, más completo)
#   powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1 -Cada 30       vigilancia continua: revisa cada 30 segundos, con barrido, y avisa lo que cambia
#   powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1 -MacCompleta   muestra las MAC completas (por defecto van tapadas para proyectar)

param([switch]$Barrido, [int]$Cada = 0, [switch]$MacCompleta)

. (Join-Path $PSScriptRoot 'RedLocal.ps1')

function Agregar-Columna($base, [string]$columna, $valor) {
    $fila = [ordered]@{}
    foreach ($k in $base.Keys) { $fila[$k] = $base[$k] }
    $fila[$columna] = $valor
    return [PSCustomObject]$fila
}

function Comparar-ConInventario($inventario, $equipos, $datosRed, [bool]$macCompleta) {
    # Cruza los equipos conectados con el inventario y devuelve la lista de hallazgos.
    $hallazgos = @()
    $vistos = @{}
    $routers = @($inventario.Values | Where-Object { $_.Tipo -eq 'Router' -and (Probar-Autorizado $_) } | ForEach-Object { $_.MAC })
    $ipsPorMac = @{}
    foreach ($e in $equipos) {
        if ($e.MAC) {
            if (-not $ipsPorMac.ContainsKey($e.MAC)) { $ipsPorMac[$e.MAC] = @() }
            $ipsPorMac[$e.MAC] += $e.IP
        }
    }

    foreach ($e in $equipos) {
        $vistos[$e.Clave] = $true
        $conocido = $inventario[$e.Clave]
        $nombre = if ($e.Nombre) { $e.Nombre } elseif ($conocido) { $conocido.Nombre } else { '' }
        $tipo = if ($conocido -and $conocido.Tipo) { $conocido.Tipo } else { $e.Tipo }
        $base = [ordered]@{ IP = $e.IP; MAC = (Mostrar-Mac $e.MAC $macCompleta); Fabricante = (Obtener-Fabricante $e.MAC); Nombre = $nombre; Tipo = $tipo }
        $responsable = if ($conocido) { $conocido.Responsable } else { '' }
        if ($e.IP -eq $datosRed.IP) {
            $hallazgos += [PSCustomObject]@{ Nivel = 'OK'; Clave = $e.Clave; MacReal = $e.MAC; Fila = (Agregar-Columna $base 'Responsable' $responsable) }
            continue
        }

        $motivo = ''
        if ($e.IP -eq $datosRed.Router -and $routers.Count -and $e.MAC -notin $routers) {
            $motivo = 'la MAC del router cambió: cambio de router o posible ARP spoofing'
            foreach ($anterior in $routers) { $vistos[$anterior] = $true }      # el router anterior no se informa además como ausente
        } elseif ($e.IP -ne $datosRed.Router -and $datosRed.Router -in @($ipsPorMac[$e.MAC])) {
            $motivo = 'usa la misma MAC que el router: posible man in the middle (ARP spoofing)'
        } elseif (-not $conocido) {
            $motivo = 'no está en el inventario'
        } elseif (-not (Probar-Autorizado $conocido)) {
            $estado = if ($conocido.Autorizado) { $conocido.Autorizado } else { 'sin dato' }
            $motivo = "figura en el inventario como «$estado», sin autorizar"
        }
        if ($motivo) {
            $hallazgos += [PSCustomObject]@{ Nivel = 'ALERTA'; Clave = $e.Clave; MacReal = $e.MAC; Fila = (Agregar-Columna $base 'Motivo' $motivo) }
            continue
        }

        $hallazgos += [PSCustomObject]@{ Nivel = 'OK'; Clave = $e.Clave; MacReal = $e.MAC; Fila = (Agregar-Columna $base 'Responsable' $responsable) }
        $cambios = @()
        if ($conocido.IP -ne $e.IP) { $cambios += "cambió de IP: antes $($conocido.IP)" }
        if (@($ipsPorMac[$e.MAC]).Count -gt 1) { $cambios += 'la misma MAC responde por varias IP: ' + (@($ipsPorMac[$e.MAC]) -join ', ') }
        foreach ($cambio in $cambios) {
            $hallazgos += [PSCustomObject]@{ Nivel = 'CAMBIO'; Clave = "$($e.Clave)|$cambio"; MacReal = $e.MAC
                                             Fila = [PSCustomObject][ordered]@{ IP = $e.IP; Nombre = $nombre; Tipo = $tipo; Cambio = $cambio } }
        }
    }

    foreach ($clave in @($inventario.Keys)) {
        $fila = $inventario[$clave]
        if (-not $vistos[$clave] -and (Probar-Autorizado $fila)) {
            $hallazgos += [PSCustomObject]@{ Nivel = 'AUSENTE'; Clave = $clave; MacReal = $fila.MAC
                                             Fila = [PSCustomObject][ordered]@{ 'Última IP' = $fila.IP; Nombre = $fila.Nombre; Tipo = $fila.Tipo
                                                                                Responsable = $fila.Responsable; 'Última vez' = $fila.'Última vez' } }
        }
    }
    return , $hallazgos
}

function Registrar-Alertas($alertas) {
    foreach ($a in $alertas) {
        $linea = @((Get-Date -Format 's'), 'ALERTA', $a.Fila.Motivo, $a.Fila.IP, $a.MacReal, $a.Fila.Nombre) -join "`t"
        Add-Content -Path $ArchivoRegistro -Value $linea -Encoding UTF8
    }
}

function Mostrar-Informe($hallazgos) {
    $secciones = @(@('ALERTA', 'ALERTAS', 'Red'), @('CAMBIO', 'CAMBIOS', 'Yellow'), @('OK', 'EN REGLA', 'Green'), @('AUSENTE', 'AUSENTES', 'DarkGray'))
    foreach ($s in $secciones) {
        $filas = @($hallazgos | Where-Object { $_.Nivel -eq $s[0] } | ForEach-Object { $_.Fila })
        if ($filas.Count) {
            Write-Host "$($s[1]) ($($filas.Count))" -ForegroundColor $s[2]
            Imprimir-Tabla $filas $(if ($s[0] -eq 'ALERTA') { 'Red' } else { '' })
            Write-Host ''
        }
    }
}

$inventario = Leer-Inventario
if ($inventario.Count -eq 0) { Write-Host 'No hay inventario (inventario-activos.csv). Primero corré  .\escanear-red.ps1'; exit 1 }
$conBarrido = $Barrido.IsPresent -or ($Cada -gt 0)

Write-Host 'Relevando la red...'
$relevamiento = Relevar-Red $conBarrido
$hallazgos = Comparar-ConInventario $inventario $relevamiento.Equipos $relevamiento.Red $MacCompleta.IsPresent
$autorizados = @($inventario.Values | Where-Object { Probar-Autorizado $_ }).Count
Mostrar-Encabezado 'VIGILANCIA DE LA RED' $relevamiento.Red (Obtener-Metodo $conBarrido $relevamiento.Red)
Write-Host "  $('Inventario'.PadRight(17)) " -ForegroundColor DarkGray -NoNewline
Write-Host "inventario-activos.csv · $($inventario.Count) equipos · autorizados: $autorizados`n"
Mostrar-Informe $hallazgos

$alertas = @($hallazgos | Where-Object { $_.Nivel -eq 'ALERTA' })
Registrar-Alertas $alertas
$cuenta = @{}
foreach ($nivel in 'ALERTA', 'CAMBIO', 'OK', 'AUSENTE') { $cuenta[$nivel] = @($hallazgos | Where-Object { $_.Nivel -eq $nivel }).Count }
$resumen = "Resultado: alertas: $($cuenta.ALERTA) · cambios: $($cuenta.CAMBIO) · en regla: $($cuenta.OK) · ausentes: $($cuenta.AUSENTE)"
if ($alertas.Count) { Write-Host "$resumen · alertas guardadas en alertas-red.log" -ForegroundColor Red } else { Write-Host $resumen -ForegroundColor Green }

if ($Cada -le 0) { if ($alertas.Count) { exit 2 } else { exit 0 } }

Write-Host "`nVigilancia continua: una revisión cada $Cada segundos. Control + C para cortar." -ForegroundColor White
$estado = @{}
foreach ($h in $hallazgos) { if ($h.Nivel -in 'ALERTA', 'OK') { $estado[$h.Clave] = $h } }
while ($true) {
    Start-Sleep -Seconds $Cada
    $relevamiento = Relevar-Red $true
    $hallazgos = Comparar-ConInventario $inventario $relevamiento.Equipos $relevamiento.Red $MacCompleta.IsPresent
    $actual = @{}
    foreach ($h in $hallazgos) { if ($h.Nivel -in 'ALERTA', 'OK') { $actual[$h.Clave] = $h } }
    $hora = Get-Date -Format 'HH:mm:ss'
    foreach ($clave in @($actual.Keys)) {
        $h = $actual[$clave]
        $quien = (@($h.Fila.IP, $h.Fila.MAC, $h.Fila.Fabricante, $h.Fila.Nombre, $h.Fila.Tipo) | Where-Object { $_ }) -join ' · '
        if ($h.Nivel -eq 'ALERTA' -and (-not $estado[$clave] -or $estado[$clave].Nivel -ne 'ALERTA')) {
            Write-Host "$hora  ALERTA    $quien · $($h.Fila.Motivo)" -ForegroundColor Red
            Registrar-Alertas @($h)
        } elseif ($h.Nivel -eq 'OK' -and -not $estado[$clave]) {
            Write-Host "$hora  volvió    $quien" -ForegroundColor Green
        }
    }
    foreach ($clave in @($estado.Keys)) {
        if (-not $actual[$clave]) {
            $f = $estado[$clave].Fila
            Write-Host ("$hora  se fue    " + ((@($f.IP, $f.Nombre, $f.Tipo) | Where-Object { $_ }) -join ' · ')) -ForegroundColor DarkGray
        }
    }
    $enAlerta = @($actual.Values | Where-Object { $_.Nivel -eq 'ALERTA' }).Count
    Write-Host "$hora  $($relevamiento.Equipos.Count) equipos conectados · $enAlerta en alerta" -ForegroundColor DarkGray
    $estado = $actual
}
