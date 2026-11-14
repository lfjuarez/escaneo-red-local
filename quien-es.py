#!/usr/bin/env python3
"""
quien-es.py — de una IP a la ficha del equipo (Mac y Linux)
===========================================================

Le das una IP de tu red y te muestra todo lo que se puede averiguar de ese equipo, dato por dato,
y al lado de cada dato el comando del que salió. Sirve para aprender el camino «a mano» y para
investigar un equipo puntual que apareció en el escaneo (por ejemplo, uno que nadie reconoce).

Uso:
    python3 quien-es.py 192.168.0.7

Ejemplo de lo que muestra (datos inventados):
    FICHA DE 192.168.0.7
      MAC          94:e6:ba:xx:xx:xx        arp -an | grep "(192.168.0.7)"
      Fabricante   Samsung                  primeros 3 bytes de la MAC (94:e6:ba) en fabricantes-mac.txt
      Responde     sí · 5 ms                ping -c 2 192.168.0.7
      Sistema      Linux, Android o Apple   el TTL de esa respuesta (64)
      Nombre       TV del living            lo que el equipo anuncia por mDNS
      Modelo       Samsung QN55             la ficha de su anuncio (manufacturer, model)
      Servicios    AirPlay :7000, Chromecast :8009
      Tipo         TV o reproductor         deducido de sus servicios

Usalo solo en tu red o con autorización.
"""
import argparse
import ipaddress
import sys

import red_local as rl   # el motor: ahí está, comentado, cómo se obtiene cada dato


def main():
    p = argparse.ArgumentParser(description="Muestra la ficha de un equipo de tu red a partir de su IP.")
    p.add_argument("ip", help="la IP del equipo, por ejemplo 192.168.0.7")
    p.add_argument("--mac", action="store_true", help="mostrar la MAC completa")
    args = p.parse_args()
    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        sys.exit(f"«{args.ip}» no es una IP. Ejemplo: python3 quien-es.py 192.168.0.7")

    red = rl.leer_red()
    es_propia = args.ip == red.ip

    # 1. El ping: además de medir, obliga a la computadora a averiguar la MAC (queda en la tabla ARP).
    rl.progreso("haciendo ping")
    _, (responde, latencia, ttl) = rl.sondear(args.ip)

    # 2. La MAC sale de la tabla ARP; el fabricante, de sus 3 primeros bytes.
    mac = red.mac if es_propia else rl.leer_vecinos().get(args.ip, "")
    equipo = rl.Equipo(ip=args.ip, mac=mac, responde=responde, latencia=latencia, ttl=ttl)
    fabricante = rl.fabricante_de(equipo, rl.cargar_fabricantes())

    # 3. El nombre: lo que responde la red cuando se pregunta por esa IP (DNS inverso).
    rl.progreso("preguntando el nombre")
    _, nombre_red = rl.nombre_inverso(args.ip, red.router)

    # 4. Lo que el equipo anuncia: se escuchan todos los anuncios y se quedan los de esta IP.
    rl.progreso("escuchando lo que el equipo anuncia (unos 15 segundos)")
    anuncios = [a for a in rl.leer_anuncios() if a.ip == args.ip]
    rl.fin_progreso()

    nombres, marca, modelo = [], "", ""
    for a in anuncios:
        etiqueta, clase = rl.SERVICIOS.get(a.tipo, (a.tipo.split(".")[0].lstrip("_"), ""))
        equipo.servicios[etiqueta] = a.puerto
        equipo.clases.add(clase)
        n = rl._nombre_presentable(a.datos.get("fn") or a.instancia)
        if n and n not in nombres:
            nombres.append(n)
        marca = marca or a.datos.get("manufacturer") or a.datos.get("usb_MFG") or ""
        modelo = modelo or a.datos.get("model") or a.datos.get("md") or a.datos.get("usb_MDL") or ""
        nombre_red = nombre_red or a.host
    if es_propia:
        modelo = red.equipo
    equipo.modelo = modelo
    equipo.tipo = rl._tipo_de(equipo, red)
    sistema = red.sistema if es_propia else (rl.SISTEMA_POR_TTL.get(ttl, f"poco común (TTL {ttl})") if ttl else "")

    # 5. La ficha: cada dato con el comando del que salió.
    ip = args.ip
    filas = [
        ("Rol", "esta computadora" if es_propia else "router" if ip == red.router else "", "configuración de red de esta computadora"),
        ("MAC", rl.mostrar_mac(mac, args.mac) or "no se pudo averiguar",
         ("ifconfig (la propia)" if rl.ES_MAC else "ip link (la propia)") if es_propia else f'arp -an | grep "({ip})"'),
        ("Fabricante", fabricante, "" if not mac else
         ("el segundo carácter de la MAC es 2, 6, A o E: es inventada y oculta la marca" if equipo.mac_privada
          else f"primeros 3 bytes de la MAC ({mac[:8]}) en fabricantes-mac.txt")),
        ("Responde", (f"sí · {latencia:.0f} ms" if responde else "no responde al ping (puede estar dormido o bloquearlo)") if not es_propia else "",
         f"ping -c 2 {ip}"),
        ("Sistema", sistema, "el sistema de esta computadora" if es_propia else (f"el TTL de esa respuesta ({ttl})" if ttl else "")),
        ("Nombre", ", ".join(nombres) or nombre_red or "?", "lo que el equipo anuncia por mDNS" if nombres else
         (f"dig +short -x {ip} @224.0.0.251 -p 5353" if rl.ES_MAC else f"avahi-resolve-address {ip}")),
        ("Nombre de red", nombre_red if nombres else "", "el nombre .local que figura en su anuncio"),
        ("Modelo", " ".join(x for x in (marca, modelo) if x), "la ficha de su anuncio (manufacturer, model)" if not es_propia else "system_profiler"),
        ("Servicios", ", ".join(f"{s} :{p}" for s, p in sorted(equipo.servicios.items())), "dns-sd -Z <tipo> local." if rl.ES_MAC else "avahi-browse -art"),
        ("Tipo", equipo.tipo, "deducido de su modelo y sus servicios" if equipo.tipo and not es_propia else ""),
    ]
    print(rl.pintar(f"\nFICHA DE {ip}", rl.NEGRITA))
    ancho = max(len(str(v)) for _, v, _ in filas if v)
    for etiqueta, valor, origen in filas:
        if valor:
            print(f"  {etiqueta.ljust(14)} {str(valor).ljust(ancho)}   {rl.pintar(origen, rl.GRIS)}")
    if not anuncios and not es_propia:
        print(rl.pintar("\n  Este equipo no anuncia servicios. Los celulares casi nunca lo hacen y usan MAC privada, para que no los rastreen.", rl.GRIS))
    print()


if __name__ == "__main__":
    main()
