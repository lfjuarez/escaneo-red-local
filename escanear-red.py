#!/usr/bin/env python3
"""
escanear-red.py — escaneo inicial de la red local (Mac y Linux)
================================================================

¿Para qué sirve?
    Para saber qué hay conectado a una red: cada equipo con su IP, MAC, fabricante, nombre, tipo,
    modelo, sistema estimado, latencia y los servicios que anuncia. Es lo primero que hace un analista
    al llegar a una red (y también un atacante: se llama reconocimiento, MITRE ATT&CK T1018).

¿Qué deja guardado?
    inventario-activos.csv: la lista de equipos que hay ahora. Es el «inventario de activos» (CIS Control 1).
    Se abre con Excel o Google Sheets. En la columna «Autorizado» se marca «sí» para cada equipo que
    se reconoce. Después, vigilar-red.py compara la red contra esa lista y avisa si aparece algo raro.

Cómo se usa (en la terminal, parado en esta carpeta):
    python3 escanear-red.py              escaneo pasivo: tabla ARP + anuncios de los equipos
    python3 escanear-red.py --barrido    además saluda a todas las direcciones de la red (activo, más completo)
    python3 escanear-red.py --aprobar    marca como autorizados todos los equipos pendientes del inventario
    python3 escanear-red.py --mac        muestra las MAC completas (por defecto van tapadas para proyectar)

Ejemplo de lo que muestra (datos inventados):
    IP           MAC                Fabricante  Nombre         Tipo              Sistema                 Latencia  Servicios
    192.168.0.1  a4:2b:b0:xx:xx:xx  TP-Link     router         Router            Linux, Android o Apple  3 ms
    192.168.0.7  94:e6:ba:xx:xx:xx  Samsung     TV del living  TV o reproductor  Linux, Android o Apple  5 ms      AirPlay :7000
    192.168.0.9  fe:7f:34:xx:xx:xx  privada                    Celular o compu                           no responde

Usalo solo en tu red o con autorización. En Argentina, acceder sin autorización a un sistema es delito (ley 26.388).
"""
import argparse
from collections import Counter

import red_local as rl   # el motor: ahí está cómo se obtiene cada dato (leelo, está comentado)


def main():
    # 1. Las opciones que se pueden pasar al programa (--barrido, --aprobar, --mac).
    p = argparse.ArgumentParser(description="Escaneo inicial de la red local. Usalo solo en tu red o con autorización.")
    p.add_argument("--barrido", action="store_true", help="descubrimiento activo: un ping a cada dirección de la red")
    p.add_argument("--aprobar", action="store_true", help="marcar como autorizados los equipos pendientes del inventario")
    p.add_argument("--mac", action="store_true", help="mostrar las MAC completas")
    args = p.parse_args()

    # 2. Relevar la red: todo el trabajo lo hace el motor (red_local.relevar).
    red, equipos = rl.relevar(barrido=args.barrido, avisar=rl.progreso)
    rl.fin_progreso()
    fabricantes = rl.cargar_fabricantes()
    if not fabricantes:
        print("Aviso: falta fabricantes-mac.txt junto a los scripts; la columna Fabricante queda sin datos.")

    # 3. Mostrar: primero los datos de la red y después la tabla, un equipo por renglón.
    rl.encabezado("ESCANEO DE LA RED", red, rl.metodo_usado(args.barrido, red))
    rl.imprimir_tabla([rl.fila_de(e, fabricantes, args.mac) for e in equipos])

    # 4. Un resumen en números, para leerlo de un vistazo.
    tipos = Counter(e.tipo or "sin identificar" for e in equipos)
    print(f"\n{len(equipos)} equipos · {sum(e.responde for e in equipos)} responden al ping · "
          f"{sum(e.mac_privada for e in equipos)} con MAC privada · {sum(len(e.servicios) for e in equipos)} servicios anunciados")
    print("Por tipo: " + " · ".join(f"{n} {t}" for t, n in tipos.most_common()))

    # 5. Guardar el inventario. Si ya existía, se actualiza sin borrar lo que cargó una persona.
    inventario = rl.leer_inventario()
    primera_vez = not inventario
    nuevas = rl.registrar(inventario, equipos, fabricantes)
    if args.aprobar:
        for fila in inventario.values():
            if not rl.autorizado(fila):
                fila["Autorizado"] = "sí"
    rl.guardar_inventario(inventario)

    # 6. Decir cómo quedó el inventario y cuál es el paso siguiente.
    pendientes = sum(not rl.autorizado(f) for f in inventario.values())
    print(rl.pintar(f"\nInventario: {rl.INVENTARIO.name}", rl.NEGRITA)
          + f" · {len(inventario)} equipos · autorizados: {len(inventario) - pendientes} · pendientes: {pendientes}")
    if primera_vez:
        print("Es el primer escaneo: quedó guardado como inventario de activos.")
    elif nuevas:
        print(rl.pintar(f"{len(nuevas)} equipos que no estaban en el inventario: ", rl.AMARILLO)
              + ", ".join(inventario[c]["IP"] for c in nuevas))
    if pendientes:
        print("Siguiente paso: abrí el archivo y poné «sí» en la columna Autorizado de los equipos que reconocés,\n"
              "o aprobá todos con  python3 escanear-red.py --aprobar  · Después, vigilá la red con  python3 vigilar-red.py")
    else:
        print("Todo el inventario está autorizado. Vigilá la red con  python3 vigilar-red.py")


if __name__ == "__main__":
    main()
