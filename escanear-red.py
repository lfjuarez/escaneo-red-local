#!/usr/bin/env python3
"""Escaneo inicial de la red local (Mac y Linux).

Descubre los equipos de la red donde se corre y muestra una tabla con IP, MAC, fabricante, nombre,
tipo de equipo, modelo, sistema estimado, latencia y servicios anunciados.
El resultado se guarda en inventario-activos.csv: es el inventario contra el que después compara vigilar-red.py.

Usalo solo en tu red o con autorización.

  python3 escanear-red.py              descubrimiento pasivo (tabla ARP + anuncios)
  python3 escanear-red.py --barrido    además saluda a todas las direcciones de la red (activo, más completo)
  python3 escanear-red.py --aprobar    marca como autorizados los equipos pendientes del inventario
  python3 escanear-red.py --mac        muestra las MAC completas (por defecto van tapadas para proyectar)
"""
import argparse
from collections import Counter

import red_local as rl


def main():
    p = argparse.ArgumentParser(description="Escaneo inicial de la red local. Usalo solo en tu red o con autorización.")
    p.add_argument("--barrido", action="store_true", help="descubrimiento activo: un ping a cada dirección de la red")
    p.add_argument("--aprobar", action="store_true", help="marcar como autorizados los equipos pendientes del inventario")
    p.add_argument("--mac", action="store_true", help="mostrar las MAC completas")
    args = p.parse_args()

    red, equipos = rl.relevar(barrido=args.barrido, avisar=rl.progreso)
    rl.fin_progreso()
    fabricantes = rl.cargar_fabricantes()
    if not fabricantes:
        print("Aviso: falta fabricantes-mac.txt junto a los scripts; la columna Fabricante queda sin datos.")

    rl.encabezado("ESCANEO DE LA RED", red, rl.metodo_usado(args.barrido, red))
    rl.imprimir_tabla([rl.fila_de(e, fabricantes, args.mac) for e in equipos])

    tipos = Counter(e.tipo or "sin identificar" for e in equipos)
    print(f"\n{len(equipos)} equipos · {sum(e.responde for e in equipos)} responden al ping · "
          f"{sum(e.mac_privada for e in equipos)} con MAC privada · {sum(len(e.servicios) for e in equipos)} servicios anunciados")
    print("Por tipo: " + " · ".join(f"{n} {t}" for t, n in tipos.most_common()))

    inventario = rl.leer_inventario()
    primera_vez = not inventario
    nuevas = rl.registrar(inventario, equipos, fabricantes)
    if args.aprobar:
        for fila in inventario.values():
            if not rl.autorizado(fila):
                fila["Autorizado"] = "sí"
    rl.guardar_inventario(inventario)

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
