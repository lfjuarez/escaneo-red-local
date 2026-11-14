#!/usr/bin/env python3
"""Vigilancia de la red local contra el inventario de activos (Mac y Linux).

Compara lo que hay conectado ahora con inventario-activos.csv (lo crea escanear-red.py) y avisa:
  ALERTA    un equipo que no está en el inventario o que no está autorizado
  ALERTA    señales de ARP spoofing: la MAC del router cambió, o un equipo usa la misma MAC que el router
  CAMBIO    un equipo autorizado cambió de IP, de nombre o anuncia un servicio nuevo
  AUSENTE   un equipo autorizado que ahora no se ve
Las alertas también se guardan en alertas-red.log, como las recibiría un SIEM.
Termina con código 2 si hubo alertas, para poder usarlo en una tarea programada.

Usalo solo en tu red o con autorización.

  python3 vigilar-red.py               una revisión pasiva (tabla ARP + anuncios)
  python3 vigilar-red.py --barrido     además saluda a todas las direcciones de la red (activo, más completo)
  python3 vigilar-red.py --cada 30     vigilancia continua: revisa cada 30 segundos, con barrido, y avisa lo que cambia
  python3 vigilar-red.py --mac         muestra las MAC completas (por defecto van tapadas para proyectar)
"""
import argparse
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

import red_local as rl


@dataclass
class Hallazgo:
    nivel: str     # ALERTA, CAMBIO, OK o AUSENTE
    clave: str     # identifica el hallazgo entre una revisión y la siguiente
    fila: dict     # lo que se muestra
    mac: str = ""  # la MAC completa, para el registro de alertas


def comparar(inventario, equipos, red, fabricantes, mac_completa, con_anuncios):
    """Cruza los equipos conectados con el inventario y devuelve la lista de hallazgos."""
    hallazgos = []
    vistos = set()
    routers = {f["MAC"] for f in inventario.values() if f["Tipo"] == "Router" and rl.autorizado(f)}
    ips_por_mac = defaultdict(list)
    for e in equipos:
        if e.mac:
            ips_por_mac[e.mac].append(e.ip)

    for e in equipos:
        vistos.add(e.clave)
        conocido = inventario.get(e.clave, {})
        base = {"IP": e.ip, "MAC": rl.mostrar_mac(e.mac, mac_completa), "Fabricante": rl.fabricante_de(e, fabricantes),
                "Nombre": e.nombre or conocido.get("Nombre", ""), "Tipo": conocido.get("Tipo") or e.tipo}
        if e.ip == red.ip:
            hallazgos.append(Hallazgo("OK", e.clave, {**base, "Responsable": conocido.get("Responsable", "")}))
            continue

        motivo = ""
        if e.ip == red.router and routers and e.mac not in routers:
            motivo = "la MAC del router cambió: cambio de router o posible ARP spoofing"
            vistos.update(routers)        # el router anterior no se informa además como ausente
        elif e.ip != red.router and red.router in ips_por_mac.get(e.mac, []):
            motivo = "usa la misma MAC que el router: posible man in the middle (ARP spoofing)"
        elif not conocido:
            motivo = "no está en el inventario"
        elif not rl.autorizado(conocido):
            motivo = f"figura en el inventario como «{conocido.get('Autorizado') or 'sin dato'}», sin autorizar"
        if motivo:
            hallazgos.append(Hallazgo("ALERTA", e.clave, {**base, "Motivo": motivo}, e.mac))
            continue

        hallazgos.append(Hallazgo("OK", e.clave, {**base, "Responsable": conocido.get("Responsable", "")}))
        cambios = []
        if conocido["IP"] != e.ip:
            cambios.append(f"cambió de IP: antes {conocido['IP']}")
        if len(ips_por_mac.get(e.mac, [])) > 1:
            cambios.append("la misma MAC responde por varias IP: " + ", ".join(ips_por_mac[e.mac]))
        if con_anuncios:
            if e.nombre and conocido["Nombre"] and e.nombre != conocido["Nombre"]:
                cambios.append(f"cambió de nombre: antes «{conocido['Nombre']}»")
            nuevos = set(e.servicios) - rl.servicios_de(conocido)
            if nuevos:
                cambios.append("anuncia servicios nuevos: " + ", ".join(sorted(nuevos)))
        for cambio in cambios:
            hallazgos.append(Hallazgo("CAMBIO", f"{e.clave}|{cambio}", {"IP": e.ip, "Nombre": base["Nombre"], "Tipo": base["Tipo"], "Cambio": cambio}))

    for clave, f in inventario.items():
        if clave not in vistos and rl.autorizado(f):
            hallazgos.append(Hallazgo("AUSENTE", clave, {"Última IP": f["IP"], "Nombre": f["Nombre"], "Tipo": f["Tipo"],
                                                         "Responsable": f["Responsable"], "Última vez": f["Última vez"]}))
    return hallazgos


def registrar_alertas(hallazgos):
    with rl.REGISTRO.open("a", encoding="utf-8") as registro:
        for h in hallazgos:
            f = h.fila
            registro.write("\t".join([datetime.now().isoformat(timespec="seconds"), "ALERTA", f["Motivo"], f["IP"], h.mac, f["Nombre"]]) + "\n")


def informe(hallazgos):
    secciones = (("ALERTA", "ALERTAS", rl.ROJO), ("CAMBIO", "CAMBIOS", rl.AMARILLO),
                 ("OK", "EN REGLA", rl.VERDE), ("AUSENTE", "AUSENTES", rl.GRIS))
    for nivel, titulo, color in secciones:
        filas = [h.fila for h in hallazgos if h.nivel == nivel]
        if filas:
            print(rl.pintar(f"{titulo} ({len(filas)})", f"{rl.NEGRITA};{color}"))
            rl.imprimir_tabla(filas, color=(lambda f: color) if nivel == "ALERTA" else None)
            print()


def revisar(inventario, fabricantes, args, completo):
    red, equipos = rl.relevar(barrido=args.barrido or bool(args.cada), anuncios=completo, avisar=rl.progreso if completo else (lambda t: None))
    rl.fin_progreso()
    return red, equipos, comparar(inventario, equipos, red, fabricantes, args.mac, completo)


def main():
    p = argparse.ArgumentParser(description="Vigila la red local contra el inventario de activos. Usalo solo en tu red o con autorización.")
    p.add_argument("--barrido", action="store_true", help="descubrimiento activo: un ping a cada dirección de la red")
    p.add_argument("--cada", type=int, metavar="SEGUNDOS", help="vigilancia continua (siempre con barrido); se corta con Control + C")
    p.add_argument("--mac", action="store_true", help="mostrar las MAC completas")
    args = p.parse_args()
    sys.stdout.reconfigure(line_buffering=True)     # cada línea sale al instante, también si se guarda en un archivo

    inventario = rl.leer_inventario()
    if not inventario:
        sys.exit(f"No hay inventario ({rl.INVENTARIO.name}). Primero corré  python3 escanear-red.py")
    fabricantes = rl.cargar_fabricantes()

    red, equipos, hallazgos = revisar(inventario, fabricantes, args, completo=True)
    autorizados = sum(rl.autorizado(f) for f in inventario.values())
    rl.encabezado("VIGILANCIA DE LA RED", red, rl.metodo_usado(args.barrido or bool(args.cada), red))
    print(f"  {rl.pintar('Inventario'.ljust(17), rl.GRIS)} {rl.INVENTARIO.name} · {len(inventario)} equipos · autorizados: {autorizados}\n")
    informe(hallazgos)
    alertas = [h for h in hallazgos if h.nivel == "ALERTA"]
    registrar_alertas(alertas)
    cuenta = {n: sum(h.nivel == n for h in hallazgos) for n in ("ALERTA", "CAMBIO", "OK", "AUSENTE")}
    resumen = f"alertas: {cuenta['ALERTA']} · cambios: {cuenta['CAMBIO']} · en regla: {cuenta['OK']} · ausentes: {cuenta['AUSENTE']}"
    print(rl.pintar("Resultado: " + resumen, f"{rl.NEGRITA};{rl.ROJO if alertas else rl.VERDE}")
          + (f" · alertas guardadas en {rl.REGISTRO.name}" if alertas else ""))

    if not args.cada:
        sys.exit(2 if alertas else 0)

    print(rl.pintar(f"\nVigilancia continua: una revisión cada {args.cada} segundos. Control + C para cortar.", rl.NEGRITA))
    estado = {h.clave: h for h in hallazgos if h.nivel in ("ALERTA", "OK")}
    try:
        while True:
            time.sleep(args.cada)
            _, equipos, hallazgos = revisar(inventario, fabricantes, args, completo=False)
            actual = {h.clave: h for h in hallazgos if h.nivel in ("ALERTA", "OK")}
            hora = datetime.now().strftime("%H:%M:%S")
            for clave, h in actual.items():
                f = h.fila
                quien = " · ".join(x for x in (f["IP"], f["MAC"], f["Fabricante"], f["Nombre"], f["Tipo"]) if x)
                if h.nivel == "ALERTA" and (clave not in estado or estado[clave].nivel != "ALERTA"):
                    print(rl.pintar(f"{hora}  ALERTA    {quien} · {f['Motivo']}", rl.ROJO))
                    registrar_alertas([h])
                elif h.nivel == "OK" and clave not in estado:
                    print(rl.pintar(f"{hora}  volvió    {quien}", rl.VERDE))
            for clave, h in estado.items():
                if clave not in actual:
                    f = h.fila
                    print(rl.pintar(f"{hora}  se fue    " + " · ".join(x for x in (f["IP"], f["Nombre"], f["Tipo"]) if x), rl.GRIS))
            print(rl.pintar(f"{hora}  {len(equipos)} equipos conectados · {sum(h.nivel == 'ALERTA' for h in actual.values())} en alerta", rl.GRIS))
            estado = actual
    except KeyboardInterrupt:
        print("\nVigilancia detenida.")


if __name__ == "__main__":
    main()
