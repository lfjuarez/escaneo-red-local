# escanear-red.ps1 — escaneo inicial de la red local (Windows)
# =============================================================
#
# ¿Para qué sirve?
#   Para saber qué hay conectado a una red: cada equipo con su IP, MAC, fabricante, nombre, tipo,
#   sistema estimado y latencia. Es lo primero que hace un analista al llegar a una red (y también un
#   atacante: se llama descubrimiento, MITRE ATT&CK T1018).
#
# ¿Qué deja guardado?
#   inventario-activos.csv: el «inventario de activos» (CIS Control 1). Se abre con Excel.
#   En la columna «Autorizado» se marca «sí» para cada equipo que se reconoce. Después, vigilar-red.ps1
#   compara la red contra esa lista y avisa si aparece algo raro.
#
# Ejemplo de lo que muestra (datos inventados):
#   IP           MAC                Fabricante  Nombre         Tipo              Sistema                 Latencia
#   192.168.0.1  a4:2b:b0:xx:xx:xx  TP-Link                    Router            Linux, Android o Apple  3 ms
#   192.168.0.9  fe:7f:34:xx:xx:xx  privada                    Celular o computadora                           no responde
#
# Usalo solo en tu red o con autorización.
#
# Desde PowerShell, en la carpeta de los archivos:
#   powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1                descubrimiento pasivo (tabla de vecinos)
#   powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1 -Barrido       además saluda a todas las direcciones de la red (activo, más completo)
#   powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1 -Aprobar       marca como autorizados los equipos pendientes del inventario
#   powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1 -MacCompleta   muestra las MAC completas (por defecto van tapadas para proyectar)
# «-ExecutionPolicy Bypass» permite correr este archivo solo esta vez; no cambia la configuración de Windows.

param([switch]$Barrido, [switch]$Aprobar, [switch]$MacCompleta)

. (Join-Path $PSScriptRoot 'RedLocal.ps1')     # carga el motor: ahí está cómo se obtiene cada dato

Write-Host 'Relevando la red...'
$relevamiento = Relevar-Red $Barrido.IsPresent
$datosRed = $relevamiento.Red
$equipos = $relevamiento.Equipos
if (-not (Test-Path $BaseFabricantes)) { Write-Host 'Aviso: falta fabricantes-mac.txt junto a los scripts; la columna Fabricante queda sin datos.' }

Mostrar-Encabezado 'ESCANEO DE LA RED' $datosRed (Obtener-Metodo $Barrido.IsPresent $datosRed)
Imprimir-Tabla ($equipos | ForEach-Object { Convertir-AFila $_ $MacCompleta.IsPresent })

$responden = @($equipos | Where-Object { $_.Responde }).Count
$privadas = @($equipos | Where-Object { Probar-MacPrivada $_.MAC }).Count
Write-Host "`n$($equipos.Count) equipos · $responden responden al ping · $privadas con MAC privada"
$porTipo = $equipos | Group-Object { if ($_.Tipo) { $_.Tipo } else { 'sin identificar' } } | Sort-Object Count -Descending
Write-Host ('Por tipo: ' + (($porTipo | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ' · '))

$inventario = Leer-Inventario
$primeraVez = $inventario.Count -eq 0
$nuevas = Registrar-Equipos $inventario $equipos
if ($Aprobar) { foreach ($fila in @($inventario.Values)) { if (-not (Probar-Autorizado $fila)) { $fila.Autorizado = 'sí' } } }
Guardar-Inventario $inventario

$pendientes = @($inventario.Values | Where-Object { -not (Probar-Autorizado $_) }).Count
Write-Host "`nInventario: inventario-activos.csv · $($inventario.Count) equipos · autorizados: $($inventario.Count - $pendientes) · pendientes: $pendientes"
if ($primeraVez) {
    Write-Host 'Es el primer escaneo: quedó guardado como inventario de activos.'
} elseif ($nuevas.Count) {
    Write-Host ("$($nuevas.Count) equipos que no estaban en el inventario: " + (($nuevas | ForEach-Object { $inventario[$_].IP }) -join ', ')) -ForegroundColor Yellow
}
if ($pendientes) {
    Write-Host 'Siguiente paso: abrí el archivo y poné «sí» en la columna Autorizado de los equipos que reconocés,'
    Write-Host 'o aprobá todos con  powershell -ExecutionPolicy Bypass -File .\escanear-red.ps1 -Aprobar'
    Write-Host 'Después, vigilá la red con  powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1'
} else {
    Write-Host 'Todo el inventario está autorizado. Vigilá la red con  powershell -ExecutionPolicy Bypass -File .\vigilar-red.ps1'
}
