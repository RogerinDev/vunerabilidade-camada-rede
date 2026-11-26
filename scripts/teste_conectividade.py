#!/usr/bin/env python3
"""
teste_conectividade.py — Validador de Ambiente e Conectividade de Camada 3 (OSI)

Objetivo acadêmico:
1. Identificar automaticamente a interface de rede ativa, o endereço MAC (Camada 2)
   e o IPv4 local (Camada 3) usados para alcançar o computador alvo.
2. Verificar se as ferramentas necessárias (Scapy, Wireshark, tcpdump, Nmap, ping)
   estão instaladas no sistema.
3. Executar um teste controlado de conectividade ICMP (Echo Request / Echo Reply)
   com o alvo, extraindo métricas reais de perda de pacotes, TTL e tempo de resposta (RTT).

Não requer privilégios de superusuário (sudo) para ser executado.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys

# Redes privadas definidas explicitamente pela RFC 1918 (+ loopback RFC 1122)
REDES_PRIVADAS_RFC1918 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
)


def validar_ip_rfc1918(endereco: str) -> str:
    """Garante que o endereço informado pertença estritamente às faixas privadas RFC 1918 (ou loopback)."""
    try:
        ip_obj = ipaddress.IPv4Address(endereco)
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError(f"Endereço IPv4 inválido: {endereco}") from exc

    if not any(ip_obj in rede for rede in REDES_PRIVADAS_RFC1918):
        raise argparse.ArgumentTypeError(
            f"O endereço {endereco} não pertence às faixas privadas da RFC 1918 "
            "(10.0.0.0/8, 172.16.0.0/12 ou 192.168.0.0/16)."
        )
    return str(ip_obj)


def descobrir_rota_local(ip_destino: str) -> tuple[str, str, str]:
    """
    Usa 'ip -4 route get <destino>' para descobrir a interface de saída, o IP local
    e lê o endereço MAC físico da interface em /sys/class/net/<iface>/address.
    """
    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "get", ip_destino],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
            env={**os.environ, "LC_ALL": "C"},
        )
        saida = proc.stdout.strip()
        match_dev = re.search(r"\bdev\s+(\S+)", saida)
        match_src = re.search(r"\bsrc\s+(\S+)", saida)
        interface = match_dev.group(1) if match_dev else "desconhecida"
        ip_origem = match_src.group(1) if match_src else "desconhecido"

        caminho_mac = Path(f"/sys/class/net/{interface}/address")
        mac_local = (
            caminho_mac.read_text(encoding="utf-8").strip()
            if caminho_mac.exists()
            else "desconhecido"
        )
        return interface, ip_origem, mac_local
    except Exception:
        return "desconhecida", "desconhecido", "desconhecido"


def verificar_ferramentas() -> dict[str, bool]:
    """Verifica a presença das ferramentas do projeto no sistema operacional."""
    status: dict[str, bool] = {}

    try:
        import scapy.all  # noqa: F401
        status["Python3 + Scapy"] = True
    except Exception:
        status["Python3 + Scapy"] = False

    for binario in ("ping", "nmap", "tcpdump", "wireshark"):
        status[binario] = shutil.which(binario) is not None

    return status


def executar_ping_controlado(
    ip_alvo: str, quantidade: int, timeout: int
) -> tuple[bool, str, dict[str, str]]:
    """
    Executa 'ping' enviando 'quantidade' pacotes ICMP Echo Request e extrai TTL, perda e RTT.
    """
    cmd = ["ping", "-c", str(quantidade), "-W", str(timeout), ip_alvo]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=quantidade * timeout + 5,
            env={**os.environ, "LC_ALL": "C"},
        )
        saida = proc.stdout
        sucesso = proc.returncode == 0
    except Exception as exc:
        return False, str(exc), {}

    metricas: dict[str, str] = {}

    match_ttl = re.search(r"ttl=(\d+)", saida, re.IGNORECASE)
    if match_ttl:
        metricas["ttl_recebido"] = match_ttl.group(1)

    match_perda = re.search(
        r"(\d+)\s+packets transmitted,\s+(\d+)\s+received,.*?(\d+(?:\.\d+)?)%\s+packet loss",
        saida,
    )
    if match_perda:
        metricas["transmitidos"] = match_perda.group(1)
        metricas["recebidos"] = match_perda.group(2)
        metricas["perda_percentual"] = f"{match_perda.group(3)}%"

    match_rtt = re.search(
        r"rtt min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", saida
    )
    if match_rtt:
        metricas["rtt_min_ms"] = match_rtt.group(1)
        metricas["rtt_medio_ms"] = match_rtt.group(2)
        metricas["rtt_max_ms"] = match_rtt.group(3)

    return sucesso, saida, metricas


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validação de ambiente e teste de conectividade ICMP (Camada 3 OSI)."
    )
    parser.add_argument(
        "--alvo",
        type=validar_ip_rfc1918,
        default="192.168.1.117",
        help="Endereço IPv4 da Máquina Alvo na rede local (ex.: 192.168.1.117)",
    )
    parser.add_argument(
        "--quantidade",
        type=int,
        default=4,
        choices=range(1, 11),
        help="Quantidade de pacotes ICMP de teste (1 a 10, padrão: 4)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=2,
        help="Tempo máximo de espera por resposta em segundos (padrão: 2)",
    )
    args = parser.parse_args()

    hostname = socket.gethostname()
    interface_local, ip_local, mac_local = descobrir_rota_local(args.alvo)

    print("==============================================================================")
    print(" PROJETO CAMADA 3 (OSI) — DIAGNÓSTICO DE AMBIENTE E CONECTIVIDADE")
    print("==============================================================================")
    print(f" Máquina Local (Hostname) : {hostname}")
    print(f" Interface de Saída (L3)  : {interface_local}")
    print(f" Endereço MAC Local (L2)  : {mac_local}")
    print(f" Endereço IPv4 de Origem  : {ip_local}")
    print(f" Endereço IPv4 de Destino : {args.alvo}")
    print("------------------------------------------------------------------------------")

    print("\n[1/2] Verificando ferramentas instaladas nesta máquina:")
    ferramentas = verificar_ferramentas()
    for nome, disponivel in ferramentas.items():
        marcador = "[OK]" if disponivel else "[AUSENTE]"
        print(f"  {marcador:<10} {nome}")

    print(f"\n[2/2] Testando comunicação ICMP normal ({args.quantidade} pacotes) com {args.alvo}...")
    sucesso, saida_bruta, metricas = executar_ping_controlado(
        args.alvo, args.quantidade, args.timeout
    )

    if sucesso:
        print("  -> [SUCESSO] Comunicação bidirecional de Camada 3 confirmada!")
        print(f"  -> Pacotes Transmitidos (Echo Request - Tipo 8) : {metricas.get('transmitidos', 'N/D')}")
        print(f"  -> Pacotes Recebidos    (Echo Reply   - Tipo 0) : {metricas.get('recebidos', 'N/D')}")
        print(f"  -> Perda de Pacotes                             : {metricas.get('perda_percentual', '0%')}")
        print(f"  -> Campo TTL observado na resposta do alvo      : {metricas.get('ttl_recebido', 'N/D')}")
        if "rtt_medio_ms" in metricas:
            print(
                f"  -> Latência RTT (Mín / Média / Máx)             : "
                f"{metricas['rtt_min_ms']} ms / {metricas['rtt_medio_ms']} ms / {metricas['rtt_max_ms']} ms"
            )
    else:
        print("  -> [FALHA] O computador alvo não respondeu ao ICMP Echo Request.")
        print("     Verifique:")
        print("       1) Se os dois computadores estão conectados na mesma rede;")
        print(f"       2) Se o IP do computador alvo realmente é {args.alvo} (rode 'ip -4 a' nele);")
        print("       3) Se você está testando em casa com outra faixa de IP, passe: --alvo <IP_REAL>")
        if saida_bruta.strip():
            print("\n  Saída detalhada do comando ping:")
            for linha in saida_bruta.strip().splitlines()[-4:]:
                print(f"    {linha}")

    print("==============================================================================")
    return 0 if sucesso else 1


if __name__ == "__main__":
    sys.exit(main())
