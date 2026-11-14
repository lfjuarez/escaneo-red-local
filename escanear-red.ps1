# Escaneo inicial de la red local (Windows).
#
# Descubre los equipos de la red donde se corre y muestra una tabla con IP, MAC, fabricante, nombre,
# tipo de equipo, sistema estimado y latencia.
# El resultado se guarda en inventario-activos.csv: es el inventario contra el que después compara vigilar-red.ps1.
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

. (Join-Path $PSScriptRoot 'RedLocal.ps1')

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
    Write-Host 'o aprobá todos con  .\escanear-red.ps1 -Aprobar  · Después, vigilá la red con  .\vigilar-red.ps1'
} else {
    Write-Host 'Todo el inventario está autorizado. Vigilá la red con  .\vigilar-red.ps1'
}
