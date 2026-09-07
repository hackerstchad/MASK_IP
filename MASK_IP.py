#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MASK_IP — Calculateur avancé de masques de sous-réseau IPv4/IPv6.
Créé par HackersTchad.
Version 3.0.0
"""

import os
import sys
import math
import time
import socket
import struct
import argparse
import ipaddress


try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.align import Align
    from rich import box
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

__version__ = "3.0.0"
__author__ = "HackersTchad"


def banner():
    b = """
    ███╗   ███╗ █████╗ ███████╗██╗  ██╗        ██╗██████╗ 
    ████╗ ████║██╔══██╗██╔════╝██║ ██╔╝        ██║██╔══██╗
    ██╔████╔██║███████║███████╗█████╔╝         ██║██████╔╝
    ██║╚██╔╝██║██╔══██║╚════██║██╔═██╗         ██║██╔═══╝ 
    ██║ ╚═╝ ██║██║  ██║███████║██║  ██╗███████╗██║██║     
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝     
         Advanced Subnet Mask Calculator v""" + __version__ + """
    """
    if console:
        console.print(Panel(Align.center(b), style="bold red", border_style="red"))
    else:
        print(b)


def slow_progress(label, duration=0.6):
    if console:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold red]{task.description}"),
            BarColumn(bar_width=40, complete_style="red", finished_style="green"),
            TaskProgressColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(label, total=100)
            for i in range(0, 101, 10):
                progress.update(task, completed=i)
                time.sleep(duration / 10)
    else:
        print(f"[PROGRESS] {label} ...")
        time.sleep(duration)


def ip_to_binary(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return "".join(format(int(octet), "08b") for octet in ip_str.split("."))
        else:
            return "N/A IPv6"
    except Exception:
        return None


def ip_to_hex(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return format(int(ip_obj), "08x").upper()
        else:
            return ip_obj.exploded.replace(":", "").upper()
    except Exception:
        return None


def mask_to_cidr(mask_str):
    try:
        return ipaddress.ip_network(f"0.0.0.0/{mask_str}", strict=False).prefixlen
    except Exception:
        return None


def cidr_to_mask(cidr):
    try:
        return str(ipaddress.IPv4Network(("0.0.0.0", cidr), strict=False).netmask)
    except Exception:
        return None


def analyze_ipv4(ip_with_cidr):
    try:
        network = ipaddress.ip_network(ip_with_cidr, strict=False)
        ip_obj = ipaddress.ip_address(ip_with_cidr.split("/")[0])
        is_network = (ip_obj == network.network_address)
        is_broadcast = (ip_obj == network.broadcast_address)

        hosts = list(network.hosts())
        first_usable = hosts[0] if hosts else None
        last_usable = hosts[-1] if hosts else None
        total_hosts = len(hosts)

        return {
            "ip": str(ip_obj),
            "cidr": network.prefixlen,
            "mask": str(network.netmask),
            "wildcard": str(network.hostmask),
            "network": str(network.network_address),
            "broadcast": str(network.broadcast_address),
            "first": str(first_usable) if first_usable else "N/A",
            "last": str(last_usable) if last_usable else "N/A",
            "total_hosts": total_hosts,
            "is_network": is_network,
            "is_broadcast": is_broadcast,
            "binary_mask": ip_to_binary(str(network.netmask)),
            "binary_ip": ip_to_binary(str(ip_obj)),
            "hex_ip": ip_to_hex(str(ip_obj)),
            "hex_mask": ip_to_hex(str(network.netmask)),
            "class": get_ip_class(str(ip_obj))
        }
    except Exception as e:
        return {"error": str(e)}


def get_ip_class(ip_str):
    try:
        first_octet = int(ip_str.split(".")[0])
        if 1 <= first_octet <= 126:
            return "A"
        elif 128 <= first_octet <= 191:
            return "B"
        elif 192 <= first_octet <= 223:
            return "C"
        elif 224 <= first_octet <= 239:
            return "D (Multicast)"
        elif 240 <= first_octet <= 255:
            return "E (Expérimental)"
        else:
            return "Inconnue"
    except Exception:
        return "Inconnue"


def analyze_ipv6(ipv6_with_cidr):
    try:
        network = ipaddress.ip_network(ipv6_with_cidr, strict=False)
        ip_obj = ipaddress.ip_address(ipv6_with_cidr.split("/")[0])
        total_hosts = 2 ** (128 - network.prefixlen)
        return {
            "ip": str(ip_obj),
            "compressed": ip_obj.compressed,
            "exploded": ip_obj.exploded,
            "cidr": network.prefixlen,
            "network": str(network.network_address),
            "total_hosts": total_hosts,
            "hex": ip_to_hex(str(ip_obj))
        }
    except Exception as e:
        return {"error": str(e)}


def split_network(ip_with_cidr, new_prefix):
    try:
        parent = ipaddress.ip_network(ip_with_cidr, strict=False)
        if new_prefix <= parent.prefixlen:
            return {"error": "Le nouveau préfixe doit être supérieur au préfixe actuel."}
        subnets = list(parent.subnets(new_prefix=new_prefix))
        return {
            "parent": str(parent),
            "new_prefix": new_prefix,
            "subnet_count": len(subnets),
            "subnets": [str(s) for s in subnets]
        }
    except Exception as e:
        return {"error": str(e)}


def summarize_networks(network_list):
    try:
        nets = [ipaddress.ip_network(n, strict=False) for n in network_list]
        summary = ipaddress.collapse_addresses(nets)
        return [str(s) for s in summary]
    except Exception as e:
        return [str(e)]


def supernet(network_list):
    return summarize_networks(network_list)


def display_ipv4(info):
    if "error" in info:
        if console:
            console.print(f"[bold red]Erreur : {info['error']}[/bold red]")
        else:
            print(f"[ERREUR] {info['error']}")
        return

    table = Table(title="Analyse IPv4", box=box.DOUBLE_EDGE, style="red")
    table.add_column("Propriété", style="cyan", no_wrap=True)
    table.add_column("Valeur", style="green")

    table.add_row("Adresse IP", info["ip"])
    table.add_row("CIDR", f"/{info['cidr']}")
    table.add_row("Masque de sous-réseau", info["mask"])
    table.add_row("Wildcard", info["wildcard"])
    table.add_row("Adresse réseau", info["network"])
    table.add_row("Adresse de diffusion", info["broadcast"])
    table.add_row("Première IP utilisable", info["first"])
    table.add_row("Dernière IP utilisable", info["last"])
    table.add_row("Nombre total d'hôtes", str(info["total_hosts"]))
    table.add_row("IP réseau ?", "OUI" if info["is_network"] else "NON")
    table.add_row("IP broadcast ?", "OUI" if info["is_broadcast"] else "NON")
    table.add_row("Classe IP", info["class"])
    table.add_row("IP en binaire", info["binary_ip"])
    table.add_row("Masque en binaire", info["binary_mask"])
    table.add_row("IP en hexadécimal", info["hex_ip"])
    table.add_row("Masque en hexadécimal", info["hex_mask"])

    if console:
        console.print(table)
    else:
        for k, v in info.items():
            print(f"{k}: {v}")


def display_ipv6(info):
    if "error" in info:
        if console:
            console.print(f"[bold red]Erreur : {info['error']}[/bold red]")
        else:
            print(f"[ERREUR] {info['error']}")
        return

    table = Table(title="Analyse IPv6", box=box.DOUBLE_EDGE, style="red")
    table.add_column("Propriété", style="cyan")
    table.add_column("Valeur", style="green")

    table.add_row("Adresse IPv6", info["ip"])
    table.add_row("Compressée", info["compressed"])
    table.add_row("Éclatée", info["exploded"])
    table.add_row("CIDR", f"/{info['cidr']}")
    table.add_row("Réseau", info["network"])
    table.add_row("Nombre d'hôtes", str(info["total_hosts"]))
    table.add_row("Hexadécimal", info["hex"])

    if console:
        console.print(table)
    else:
        for k, v in info.items():
            print(f"{k}: {v}")


def display_subnets(result):
    if "error" in result:
        if console:
            console.print(f"[bold red]Erreur : {result['error']}[/bold red]")
        else:
            print(f"[ERREUR] {result['error']}")
        return

    if console:
        console.print(f"[bold yellow]Réseau parent :[/bold yellow] {result['parent']}")
        console.print(f"[bold yellow]Découpage en /{result['new_prefix']}[/bold yellow]")
        console.print(f"[bold yellow]Nombre de sous-réseaux :[/bold yellow] {result['subnet_count']}")
        table = Table(title="Liste des sous-réseaux", box=box.SIMPLE, style="red")
        table.add_column("#", style="cyan")
        table.add_column("Sous-réseau", style="green")
        for i, s in enumerate(result["subnets"][:50], 1):
            table.add_row(str(i), s)
        if len(result["subnets"]) > 50:
            table.add_row("...", f"+ {len(result['subnets']) - 50} autres")
        console.print(table)
    else:
        print(f"Réseau parent : {result['parent']}")
        print(f"Découpage en /{result['new_prefix']}")
        print(f"Nombre de sous-réseaux : {result['subnet_count']}")
        for s in result["subnets"][:20]:
            print(f"  {s}")


def display_summary(summaries):
    if console:
        table = Table(title="Agrégation de routes (Supernet)", box=box.DOUBLE_EDGE, style="red")
        table.add_column("#", style="cyan")
        table.add_column("Réseau agrégé", style="green")
        for i, s in enumerate(summaries, 1):
            table.add_row(str(i), s)
        console.print(table)
    else:
        print("Réseaux agrégés :")
        for s in summaries:
            print(f"  {s}")


def interactive_mode():
    banner()
    while True:
        if console:
            console.print("\n[bold red]MENU MASK_IP[/bold red]")
            console.print("1. Analyser une IPv4 (CIDR)")
            console.print("2. Analyser une IPv6 (CIDR)")
            console.print("3. Convertir masque <-> CIDR")
            console.print("4. Découper un réseau (VLSM)")
            console.print("5. Agréger des réseaux (Supernet)")
            console.print("6. Quitter")
        else:
            print("\nMENU MASK_IP")
            print("1. IPv4")
            print("2. IPv6")
            print("3. Masque <-> CIDR")
            print("4. Découper réseau")
            print("5. Agréger réseaux")
            print("6. Quitter")

        choice = input("\nChoix : ").strip()

        if choice == "1":
            ip = input("Entrez une IPv4 avec CIDR (ex: 192.168.1.10/24) : ").strip()
            slow_progress("Analyse IPv4 en cours")
            display_ipv4(analyze_ipv4(ip))

        elif choice == "2":
            ip = input("Entrez une IPv6 avec CIDR (ex: 2001:db8::1/64) : ").strip()
            slow_progress("Analyse IPv6 en cours")
            display_ipv6(analyze_ipv6(ip))

        elif choice == "3":
            val = input("Entrez un masque (ex: 255.255.255.0) ou un CIDR (ex: 24) : ").strip()
            slow_progress("Conversion en cours")
            if "/" in val:
                mask = cidr_to_mask(int(val.replace("/", "")))
                print(f"Masque : {mask}")
            elif "." in val:
                cidr = mask_to_cidr(val)
                print(f"CIDR : /{cidr}")
            else:
                cidr = int(val)
                print(f"Masque pour /{cidr} : {cidr_to_mask(cidr)}")

        elif choice == "4":
            net = input("Réseau parent (ex: 192.168.0.0/24) : ").strip()
            new_p = int(input("Nouveau préfixe (ex: 26) : ").strip())
            slow_progress("Découpage en sous-réseaux")
            display_subnets(split_network(net, new_p))

        elif choice == "5":
            nets = input("Réseaux séparés par des virgules (ex: 192.168.0.0/24,192.168.1.0/24) : ").strip().split(",")
            slow_progress("Agrégation des routes")
            display_summary(summarize_networks(nets))

        elif choice == "6":
            if console:
                console.print("[bold green]Bye from MASK_IP[/bold green]")
            else:
                print("Au revoir.")
            break
        else:
            print("Choix invalide.")


def main():
    parser = argparse.ArgumentParser(description="MASK_IP — Calculateur avancé de masques de sous-réseau IPv4/IPv6")
    parser.add_argument("--ip", "-i", help="IPv4 ou IPv6 avec CIDR à analyser")
    parser.add_argument("--split", "-s", help="Découper un réseau (ex: 192.168.0.0/24)")
    parser.add_argument("--prefix", "-p", type=int, help="Nouveau préfixe pour le découpage")
    parser.add_argument("--aggregate", "-a", help="Agréger des réseaux séparés par des virgules")
    parser.add_argument("--convert", "-c", help="Convertir un masque ou un CIDR")
    parser.add_argument("--interactive", "-x", action="store_true", help="Mode interactif")
    args = parser.parse_args()

    if args.interactive or not any([args.ip, args.split, args.aggregate, args.convert]):
        interactive_mode()
        return

    banner()

    if args.ip:
        slow_progress(f"Analyse de {args.ip}")
        if ":" in args.ip:
            display_ipv6(analyze_ipv6(args.ip))
        else:
            display_ipv4(analyze_ipv4(args.ip))

    elif args.split and args.prefix:
        slow_progress(f"Découpage de {args.split} en /{args.prefix}")
        display_subnets(split_network(args.split, args.prefix))

    elif args.aggregate:
        nets = args.aggregate.split(",")
        slow_progress("Agrégation des réseaux")
        display_summary(summarize_networks(nets))

    elif args.convert:
        val = args.convert
        if "/" in val:
            print(f"Masque : {cidr_to_mask(int(val.replace('/', '')))}")
        elif "." in val:
            print(f"CIDR : /{mask_to_cidr(val)}")
        else:
            print(f"Masque pour /{val} : {cidr_to_mask(int(val))}")


if __name__ == "__main__":
    main()
