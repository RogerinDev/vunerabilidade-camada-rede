#!/usr/bin/env python3
"""
demonstracao_icmp.py — Construção, Inspeção e Envio Controlado de Pacotes IPv4/ICMP (Camada 3 OSI)

Objetivo acadêmico:
Demonstrar de forma controlada, didática e segura como o cabeçalho IPv4 (Camada 3 do Modelo OSI)
armazena os endereços de origem (src) e destino (dst) sem autenticação criptográfica nativa,
comparando:
  1. Pacote ICMP normal (origem legítima da máquina emissora);
  2. Pacote ICMP com origem declarada de documentação (RFC 5737: 198.51.100.10) — Demonstração Principal;
  3. Pacote ICMP com origem fictícia verificada como livre na sub-rede local — Demonstração Complementar;
  4. Rajada ICMP controlada de curta duração (até 100 pacotes, intervalo >= 0.01s, origem RFC 5737
     fixa ou rotativa 198.51.100.10..200) para análise experimental das métricas de disponibilidade
     (pps, Delta t e detecção por limiar de IDS) sem degradar a infraestrutura do laboratório.

Importante sobre capturas (.pcap / .pcapng):
  - Este script NÃO gera falsos arquivos PCAP durante a transmissão real. A captura real
    deve ser obtida diretamente da placa de rede pelo Wireshark (no emissor) e pelo
    tcpdump (no computador alvo).
  - O parâmetro opcional '--gerar-pcap-simulado' funciona apenas no '--modo inspecao'
    para criar um arquivo estritamente DIDÁTICO/SIMULADO de estudo offline.

Limites explícitos de segurança:
  - Modos unitários ('normal', 'spoof-doc', 'spoof-lan'): máx. 20 pacotes, intervalo mín. 0.1s;
  - Modo 'rajada-controlada': lote estritamente finito de máx. 10000 pacotes (padrão: 50, ~3.2 KB totais),
    intervalo mín. 0.0s (padrão: 0.02s -> ~50 pps por ~1s), sem loops infinitos;
  - Destino restrito exclusivamente a IPs privados de laboratório (RFC 1918);
  - Origem na rajada restrita exclusivamente às faixas de documentação da IANA (RFC 5737).
"""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from scapy.all import Ether, ICMP, IP, conf, send, sr1, wrpcap

# Limites explícitos de segurança para modos unitários
MAX_PACOTES_PADRAO = 20
MIN_INTERVALO_PADRAO = 0.1

# Limites explícitos de segurança para o modo de rajada controlada (suporta lote padrão de 50 e teste de firewall até 10.000)
MAX_PACOTES_RAJADA = 10000
MIN_INTERVALO_RAJADA = 0.0

# Faixas privadas reais de rede interna (RFC 1918)
REDES_PRIVADAS_RFC1918 = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

# Faixas oficiais reservadas para documentação/ensino pela IANA (RFC 5737)
REDES_DOCUMENTACAO_RFC5737 = (
    ipaddress.IPv4Network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
)


def validar_ip_destino(endereco: str) -> str:
    """Aceita apenas endereços IPv4 estritamente dentro das faixas privadas RFC 1918 ou loopback."""
    try:
        ip_obj = ipaddress.IPv4Address(endereco)
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError(f"IP de destino inválido: {endereco}") from exc

    em_rfc1918 = any(ip_obj in rede for rede in REDES_PRIVADAS_RFC1918)
    if not (em_rfc1918 or ip_obj.is_loopback):
        raise argparse.ArgumentTypeError(
            f"Operação bloqueada: o destino {endereco} não pertence às faixas privadas RFC 1918 "
            "(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."
        )
    return str(ip_obj)


def validar_ip_origem_simulada(endereco: str) -> str:
    """
    Aceita apenas endereços das faixas de documentação (RFC 5737) ou privados (RFC 1918),
    impedindo o uso de IPs públicos reais da internet, 0.0.0.0 ou multicast.
    """
    try:
        ip_obj = ipaddress.IPv4Address(endereco)
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError(f"IP de origem simulada inválido: {endereco}") from exc

    em_rfc5737 = any(ip_obj in rede for rede in REDES_DOCUMENTACAO_RFC5737)
    em_rfc1918 = any(ip_obj in rede for rede in REDES_PRIVADAS_RFC1918)
    if (
        not (em_rfc5737 or em_rfc1918)
        or ip_obj.is_unspecified
        or ip_obj.is_multicast
        or str(ip_obj).endswith(".255")
    ):
        raise argparse.ArgumentTypeError(
            f"Operação bloqueada: {endereco} não pertence à RFC 5737 (ex: 198.51.100.10) "
            "nem a um endereço unicast válido de sub-rede privada RFC 1918."
        )
    return str(ip_obj)


def pertence_rfc5737(endereco: str) -> bool:
    """Verifica se um endereço IPv4 pertence estritamente às redes de documentação RFC 5737."""
    ip_obj = ipaddress.IPv4Address(endereco)
    return any(ip_obj in rede for rede in REDES_DOCUMENTACAO_RFC5737)


def descobrir_interface_e_ip_local(ip_destino: str) -> tuple[str | None, str | None]:
    """
    Identifica a interface de rede (ex: enp4s0) e o IP real usado para alcançar o alvo.
    Retorna (None, None) se a rota não puder ser determinada automaticamente.
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
        iface = match_dev.group(1) if match_dev else None
        ip_real = match_src.group(1) if match_src else None
        return iface, ip_real
    except Exception:
        return None, None


def obter_mac_interface(interface: str) -> str:
    """Lê o endereço físico MAC (Camada 2) da interface local no Linux."""
    caminho_mac = Path(f"/sys/class/net/{interface}/address")
    if caminho_mac.exists():
        try:
            return caminho_mac.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    return "indisponível"


def verificar_ip_livre_na_rede(ip_candidato: str) -> tuple[bool, str]:
    """
    Executa verificação preliminar de uso do endereço candidato na sub-rede local:
      1) Envia 1 ICMP Echo Request curto (ping);
      2) Consulta a tabela ARP/vizinhança local ('ip neigh show') para verificar se
         o endereço possui MAC associado (mesmo que bloqueie ping por firewall).
    Em caso de erro na execução do comando, retorna False (bloqueia por segurança).
    """
    env_padrao = {**os.environ, "LC_ALL": "C"}
    try:
        proc_ping = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip_candidato],
            capture_output=True,
            text=True,
            timeout=3,
            env=env_padrao,
        )
        if proc_ping.returncode == 0:
            return False, "O endereço respondeu ao ping (ICMP Echo Reply recebido)."

        proc_arp = subprocess.run(
            ["ip", "neigh", "show", ip_candidato],
            capture_output=True,
            text=True,
            timeout=3,
            env=env_padrao,
        )
        saida_arp = proc_arp.stdout.strip()
        if "lladdr" in saida_arp.lower():
            return (
                False,
                f"O endereço possui MAC registrado na tabela ARP local ({saida_arp}).",
            )

        return (
            True,
            "Sem resposta ao ping e sem entrada MAC na tabela ARP local "
            "(observação técnica: hosts com firewall que bloqueia ICMP e fora do cache ARP "
            "podem não responder ao ping; confirme antes na varredura 'nmap -sn').",
        )
    except Exception as exc:
        return (
            False,
            f"Falha ao executar verificação de disponibilidade ({exc}). "
            "Por segurança, o script não assume que o IP está livre.",
        )


def construir_pacote_icmp(ip_origem: str, ip_destino: str, seq: int = 1, ttl: int = 64) -> IP:
    """
    Constrói um pacote IPv4 (Camada 3) encapsulando uma mensagem ICMP Echo Request (Tipo 8, Código 0).
    """
    carga_didatica = f"DEMO_CAMADA3_SEQ_{seq:03d}".encode("ascii")
    pacote = (
        IP(src=ip_origem, dst=ip_destino, ttl=ttl, id=0x1000 + seq)
        / ICMP(type=8, code=0, id=0x04D2, seq=seq)
        / carga_didatica
    )
    return pacote


def exibir_anatomia_cabecalho(titulo: str, pacote: IP) -> None:
    """
    Materializa os bytes do pacote para que o Scapy calcule tamanho total e checksums,
    exibindo cada campo do cabeçalho IPv4 e ICMP de forma didática no terminal.
    """
    pacote_calculado = IP(bytes(pacote))
    camada_icmp = pacote_calculado[ICMP]

    def linha_box(rotulo: str, valor: str) -> str:
        conteudo = f"  {rotulo:<18} : {valor}"
        return f"  | {conteudo:<70} |"

    print("\n  +------------------------------------------------------------------------+")
    print(f"  | {titulo:<70} |")
    print("  +------------------------------------------------------------------------+")
    print(f"  | {'[CAMADA 3 — CABEÇALHO IPv4 (20 bytes)]':<70} |")
    print(linha_box("Version", str(pacote_calculado.version)))
    print(linha_box("IHL (Tam. Cab.)", f"{pacote_calculado.ihl} ({pacote_calculado.ihl * 4} bytes)"))
    print(linha_box("Total Length", f"{pacote_calculado.len} bytes"))
    print(linha_box("TTL (TimeToLive)", str(pacote_calculado.ttl)))
    print(linha_box("Protocol", f"{pacote_calculado.proto} (1 = ICMP)"))
    print(linha_box("Header Checksum", hex(pacote_calculado.chksum)))
    print(linha_box("Source IP (src)", str(pacote_calculado.src)))
    print(linha_box("Dest. IP  (dst)", str(pacote_calculado.dst)))
    print("  +------------------------------------------------------------------------+")
    print(f"  | {'[CAMADA 3 — MENSAGEM DE CONTROLE ICMP]':<70} |")
    print(linha_box("ICMP Type", f"{camada_icmp.type} (8 = Echo Request / Pedido de Ping)"))
    print(linha_box("ICMP Code", str(camada_icmp.code)))
    print(linha_box("Identifier / Seq", f"id={hex(camada_icmp.id)} / seq={camada_icmp.seq}"))
    print(linha_box("Checksum ICMP", hex(camada_icmp.chksum)))
    print("  +------------------------------------------------------------------------+")


def exigir_privilegio_root() -> None:
    """Verifica se o script está sendo executado com sudo antes de abrir Raw Socket."""
    if os.geteuid() != 0:
        print("\n[ERRO DE PERMISSÃO] Para transmitir pacotes na Camada 3 via Raw Socket,")
        print("o kernel Linux exige privilégios de superusuário (CAP_NET_RAW).")
        print("Execute novamente adicionando 'sudo' no início do comando:")
        print(f"  sudo python3 {' '.join(sys.argv)}\n")
        sys.exit(1)


def transmitir_lote_controlado(
    descricao: str,
    ip_origem: str,
    ip_destino: str,
    interface: str,
    quantidade: int,
    intervalo: float,
    aguardar_resposta: bool,
) -> None:
    """
    Envia um número pequeno e controlado de pacotes ICMP (máx. 5) com intervalo entre envios.
    """
    mac_local = obter_mac_interface(interface)
    print("\n==============================================================================")
    print(f" EXECUÇÃO: {descricao}")
    print(f" Interface local de saída : {interface} (MAC físico Camada 2: {mac_local})")
    print(f" Cabeçalho IPv4 montado   : src={ip_origem}  --->  dst={ip_destino}")
    print(f" Limite configurado       : {quantidade} pacote(s) | Intervalo: {intervalo:.2f}s")
    print("==============================================================================")

    pacote_amostra = construir_pacote_icmp(ip_origem, ip_destino, seq=1)
    exibir_anatomia_cabecalho(f"Estrutura do Cabeçalho ({descricao})", pacote_amostra)

    for seq in range(1, quantidade + 1):
        pkt = construir_pacote_icmp(ip_origem, ip_destino, seq=seq)

        if aguardar_resposta:
            inicio = time.perf_counter()
            resposta = sr1(pkt, iface=interface, timeout=1.5, verbose=0)
            rtt_ms = (time.perf_counter() - inicio) * 1000.0
            if resposta is not None and resposta.haslayer(ICMP):
                print(
                    f"  [Pacote {seq}/{quantidade}] Transmitido Echo Request (src={ip_origem}) "
                    f"--> Recebido Echo Reply de {resposta[IP].src} (TTL={resposta[IP].ttl}, RTT={rtt_ms:.2f} ms)"
                )
            else:
                print(
                    f"  [Pacote {seq}/{quantidade}] Transmitido Echo Request (src={ip_origem}) "
                    "--> Nenhuma resposta Echo Reply recebida nesta interface dentro do timeout."
                )
        else:
            send(pkt, iface=interface, verbose=0)
            print(
                f"  [Pacote {seq}/{quantidade}] Pacote transmitido pela interface local ({interface}): "
                f"IP(src={ip_origem} -> dst={ip_destino}) / ICMP(type=8, seq={seq})"
            )
            print(
                "     -> Nota: A confirmação de que este pacote chegou ao destino NÃO deve ser "
                "presumida pelo envio; verifique a captura independente no computador alvo (tcpdump -eni)."
            )

        if seq < quantidade:
            time.sleep(intervalo)


def transmitir_rajada_controlada(
    ip_origem_base: str,
    ip_destino: str,
    interface: str,
    quantidade: int,
    intervalo: float,
    rotacionar_origem: bool,
) -> None:
    """
    Executa uma rajada curta, finita e estritamente controlada (até 100 pacotes) usando IPs da
    faixa de documentação RFC 5737 para demonstrar experimentalmente o salto de frequência (pps),
    a queda do intervalo entre pacotes (Delta t) e a rotação dinâmica de origem (IP Spoofing).
    """
    mac_local = obter_mac_interface(interface)
    if rotacionar_origem:
        ultimo_octeto_final = 10 + ((quantidade - 1) % 191)
        desc_origem = f"Rotativa RFC 5737 (198.51.100.10 .. 198.51.100.{ultimo_octeto_final})"
    else:
        desc_origem = f"Fixa RFC 5737 ({ip_origem_base})"

    print("\n==============================================================================")
    print(" EXECUÇÃO: Demonstração de Rajada ICMP Controlada (Análise de Disponibilidade)")
    print(f" Interface local de saída : {interface} (MAC físico Camada 2: {mac_local})")
    print(f" Origem IPv4 configurada  : {desc_origem}")
    print(f" Destino IPv4 configurado : {ip_destino}")
    print(
        f" Limite estrito do lote   : {quantidade} pacotes (máx. {MAX_PACOTES_RAJADA}) | "
        f"Intervalo alvo: {intervalo:.3f}s"
    )
    print("==============================================================================")

    pacotes_lote: list[IP] = []
    bytes_ip_totais = 0
    for seq in range(1, quantidade + 1):
        if rotacionar_origem:
            octeto = 10 + ((seq - 1) % 191)  # Faixa 198.51.100.10 até 198.51.100.200
            ip_src_atual = f"198.51.100.{octeto}"
        else:
            ip_src_atual = ip_origem_base

        pkt = construir_pacote_icmp(ip_src_atual, ip_destino, seq=seq)
        bytes_ip_totais += len(bytes(pkt)) + 14  # Inclui cabeçalho Ethernet de 14 bytes no fio
        pacotes_lote.append(pkt)

    exibir_anatomia_cabecalho(
        "Amostra do 1º Pacote da Rajada Controlada", pacotes_lote[0]
    )

    print(f"\n[*] Iniciando transmissão controlada de {quantidade} pacotes na interface '{interface}'...")
    soquete_l3 = conf.L3socket(iface=interface)
    t_inicio = time.perf_counter()
    try:
        for idx, pkt in enumerate(pacotes_lote, start=1):
            soquete_l3.send(pkt)
            if idx in (1, quantidade) or idx % 10 == 0:
                print(
                    f"  -> Progresso [{idx:>3}/{quantidade}]: "
                    f"IP(src={pkt.src:<15} -> dst={pkt.dst}) / ICMP(type=8, seq={idx})"
                )
            if idx < quantidade:
                time.sleep(intervalo)
    finally:
        soquete_l3.close()
    duracao_real = max(0.0001, time.perf_counter() - t_inicio)

    taxa_pps = quantidade / duracao_real
    taxa_bps = bytes_ip_totais / duracao_real

    print("\n------------------------------------------------------------------------------")
    print(" MÉTRICAS MEDIDAS DA RAJADA CONTROLADA (EMISSOR)")
    print("------------------------------------------------------------------------------")
    print(f" Pacotes transmitidos     : {quantidade} pacotes (lote finito concluído)")
    print(f" Volume estimado no enlace: {bytes_ip_totais} bytes ({bytes_ip_totais / 1024:.2f} KB)")
    print(f" Tempo ativo de envio     : {duracao_real:.4f} segundos")
    print(f" Taxa efetiva atingida    : {taxa_pps:.2f} pacotes/segundo (pps)")
    print(f" Vazão efetiva no enlace  : {taxa_bps:.1f} bytes/segundo")
    print(
        " Nota metodológica        : Verifique no 'tcpdump -eni' do computador alvo e no\n"
        "                            'analise_pcap.py' o salto de pps e a queda de Delta t."
    )
    print("------------------------------------------------------------------------------")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Demonstração controlada de cabeçalhos IPv4/ICMP, IP Spoofing e Rajada Curta na Camada 3."
    )
    parser.add_argument(
        "--modo",
        choices=("inspecao", "normal", "spoof-doc", "spoof-lan", "rajada-controlada"),
        default="inspecao",
        help=(
            "Modo de operação: "
            "'inspecao' (mostra os cabeçalhos na tela sem transmitir na rede), "
            "'normal' (transmite até 20 pacotes com o IP real da máquina), "
            "'spoof-doc' (demonstração principal: transmite até 20 pacotes com IP RFC 5737 198.51.100.10), "
            "'spoof-lan' (demonstração complementar: transmite até 20 pacotes com IP livre da LAN), "
            "'rajada-controlada' (envia rajada finita de até 10000 pacotes RFC 5737 para medir pps, Delta t e firewall)."
        ),
    )
    parser.add_argument(
        "--destino",
        type=validar_ip_destino,
        default="192.168.1.117",
        help="Endereço IPv4 do computador alvo (padrão: 192.168.1.117)",
    )
    parser.add_argument(
        "--origem-real",
        type=validar_ip_destino,
        default=None,
        help="Endereço IPv4 real da máquina emissora (se omitido, é descoberto via tabela de rotas).",
    )
    parser.add_argument(
        "--origem-simulada",
        type=validar_ip_origem_simulada,
        default="198.51.100.10",
        help="Endereço IPv4 de origem para spoof-doc, spoof-lan ou rajada-controlada (padrão: 198.51.100.10)",
    )
    parser.add_argument(
        "--rotacionar-origem",
        action="store_true",
        help=(
            "Apenas para '--modo rajada-controlada': alterna sequencialmente o IP de origem a cada "
            "pacote na faixa de documentação RFC 5737 (198.51.100.10 até 198.51.100.200)."
        ),
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Interface de rede de saída (ex: enp4s0). Se omitida, é detectada automaticamente.",
    )
    parser.add_argument(
        "--quantidade",
        type=int,
        default=None,
        help=(
            f"Quantidade de pacotes: padrão 3 (máx. {MAX_PACOTES_PADRAO}) nos modos unitários; "
            f"padrão 50 (máx. {MAX_PACOTES_RAJADA}) no modo 'rajada-controlada'."
        ),
    )
    parser.add_argument(
        "--intervalo",
        type=float,
        default=None,
        help=(
            f"Intervalo entre pacotes: padrão 1.0s (mín. {MIN_INTERVALO_PADRAO}s) nos modos unitários; "
            f"padrão 0.02s (mín. {MIN_INTERVALO_RAJADA}s) no modo 'rajada-controlada'."
        ),
    )
    parser.add_argument(
        "--gerar-pcap-simulado",
        default=None,
        help=(
            "Apenas para '--modo inspecao': gera um arquivo .pcap DIDÁTICO/SIMULADO em disco "
            "para testar o analisador offline (NÃO representa captura real de placa de rede)."
        ),
    )
    args = parser.parse_args()

    # Aplica padrões e limites específicos conforme o modo selecionado
    if args.modo == "rajada-controlada":
        quantidade = args.quantidade if args.quantidade is not None else 50
        intervalo = args.intervalo if args.intervalo is not None else 0.02

        if not (1 <= quantidade <= MAX_PACOTES_RAJADA):
            print(
                f"[LIMITE DE SEGURANÇA] No modo 'rajada-controlada', a quantidade deve estar "
                f"entre 1 e {MAX_PACOTES_RAJADA} pacotes."
            )
            return 1
        if intervalo < MIN_INTERVALO_RAJADA:
            print(
                f"[LIMITE DE SEGURANÇA] No modo 'rajada-controlada', o intervalo mínimo permitido "
                f"é {MIN_INTERVALO_RAJADA}s."
            )
            return 1
        if not pertence_rfc5737(args.origem_simulada):
            print(
                "[LIMITE DE SEGURANÇA] No modo 'rajada-controlada', o endereço de origem deve "
                "pertencer estritamente às faixas de documentação da RFC 5737 (ex: 198.51.100.10)."
            )
            return 1
    else:
        quantidade = args.quantidade if args.quantidade is not None else 3
        intervalo = args.intervalo if args.intervalo is not None else 1.0

        if args.rotacionar_origem:
            print(
                "[AVISO] A opção '--rotacionar-origem' é exclusiva do '--modo rajada-controlada'."
            )
            return 1
        if not (1 <= quantidade <= MAX_PACOTES_PADRAO):
            print(
                f"[LIMITE DE SEGURANÇA] Nos modos unitários, a quantidade deve estar entre "
                f"1 e {MAX_PACOTES_PADRAO} pacotes."
            )
            return 1
        if intervalo < MIN_INTERVALO_PADRAO:
            print(
                f"[LIMITE DE SEGURANÇA] Nos modos unitários, o intervalo mínimo entre pacotes é "
                f"{MIN_INTERVALO_PADRAO}s."
            )
            return 1

    iface_detectada, ip_real_detectado = descobrir_interface_e_ip_local(args.destino)
    interface = args.interface or iface_detectada
    ip_real = args.origem_real or ip_real_detectado

    if args.modo == "inspecao":
        ip_inspecao = ip_real or "192.168.1.112"
        print("==============================================================================")
        print(" MODO INSPEÇÃO (OFFLINE) — COMPARAÇÃO DE CABEÇALHOS IPv4 / ICMP NA CAMADA 3")
        print(" AVISO: Nenhum pacote está sendo transmitido na rede neste modo.")
        print("==============================================================================")

        pkt_normal = construir_pacote_icmp(ip_inspecao, args.destino, seq=1)
        pkt_doc = construir_pacote_icmp(args.origem_simulada, args.destino, seq=2)

        exibir_anatomia_cabecalho(f"1) PACOTE NORMAL (Origem Real: {ip_inspecao})", pkt_normal)
        exibir_anatomia_cabecalho(
            f"2) PACOTE COM ORIGEM DECLARADA DIFERENTE ({args.origem_simulada})",
            pkt_doc,
        )

        if args.gerar_pcap_simulado:
            caminho_pcap = Path(args.gerar_pcap_simulado)
            caminho_pcap.parent.mkdir(parents=True, exist_ok=True)
            # MACs da faixa de documentação RFC 7042 (00:00:5e:00:53:xx) para deixar explícito
            # que se trata de um arquivo SIMULADO e não de uma captura física real.
            mac_sim_emissor = "00:00:5e:00:53:01"
            mac_sim_alvo = "00:00:5e:00:53:02"
            pacotes_simulados = []
            t_atual = time.time()

            # Fase 1 simulada: 4 pings normais (1 pps) com resposta
            for s in range(1, 5):
                req_n = Ether(src=mac_sim_emissor, dst=mac_sim_alvo) / construir_pacote_icmp(
                    ip_inspecao, args.destino, seq=s
                )
                req_n.time = t_atual
                t_atual += 0.0008
                rep_n = (
                    Ether(src=mac_sim_alvo, dst=mac_sim_emissor)
                    / IP(src=args.destino, dst=ip_inspecao, ttl=64, id=0x2000 + s)
                    / ICMP(type=0, code=0, id=0x04D2, seq=s)
                    / f"DEMO_CAMADA3_SEQ_{s:03d}".encode("ascii")
                )
                rep_n.time = t_atual
                t_atual += 1.0
                pacotes_simulados.extend([req_n, rep_n])

            # Simula pausa didática de 15 segundos entre etapas na apresentação
            t_atual += 15.0

            # Fase 2 simulada: rajada curta controlada de 25 pacotes (0.02s -> ~50 pps) com rotação RFC 5737
            for idx_b in range(1, 26):
                ip_rot = f"198.51.100.{10 + idx_b - 1}"
                req_doc = Ether(src=mac_sim_emissor, dst=mac_sim_alvo) / construir_pacote_icmp(
                    ip_rot, args.destino, seq=idx_b
                )
                req_doc.time = t_atual
                t_atual += 0.02
                pacotes_simulados.append(req_doc)

            wrpcap(str(caminho_pcap), pacotes_simulados)
            print("\n------------------------------------------------------------------------------")
            print(f" [ARQUIVO SIMULADO GERADO]: {caminho_pcap} ({len(pacotes_simulados)} pacotes)")
            print(" ATENÇÃO METODOLÓGICA: Este arquivo foi montado em memória apenas para estudo")
            print(" didático offline. NÃO utilize este arquivo como evidência de transmissão real!")
            print(" As capturas reais devem ser salvas pelo Wireshark ou tcpdump.")
            print("------------------------------------------------------------------------------")
        return 0

    if args.gerar_pcap_simulado:
        print(
            "[AVISO] O parâmetro '--gerar-pcap-simulado' só é permitido no '--modo inspecao'.\n"
            "Para registrar o tráfego real transmitido na rede, salve a captura diretamente\n"
            "pelo Wireshark (na Máquina Atacante) ou pelo tcpdump (na Máquina Alvo)."
        )
        return 1

    if not interface:
        print(
            f"[ERRO DE ROTA] Não foi possível determinar automaticamente a interface de saída para {args.destino}.\n"
            "Verifique se o cabo de rede/Wi-Fi está conectado ou informe a interface com --interface <nome>."
        )
        return 1

    if args.modo == "normal" and not ip_real:
        print(
            f"[ERRO DE ROTA] Não foi possível descobrir o IP local para {args.destino}.\n"
            "Verifique a conexão de rede ou informe seu IP real com --origem-real <IP>."
        )
        return 1

    exigir_privilegio_root()

    if args.modo == "normal":
        transmitir_lote_controlado(
            descricao="Tráfego ICMP Normal (Origem Legítima)",
            ip_origem=ip_real,
            ip_destino=args.destino,
            interface=interface,
            quantidade=quantidade,
            intervalo=intervalo,
            aguardar_resposta=True,
        )

    elif args.modo == "spoof-doc":
        transmitir_lote_controlado(
            descricao=f"Demonstração Principal de IP Spoofing — Documentação RFC 5737 ({args.origem_simulada})",
            ip_origem=args.origem_simulada,
            ip_destino=args.destino,
            interface=interface,
            quantidade=quantidade,
            intervalo=intervalo,
            aguardar_resposta=False,
        )

    elif args.modo == "spoof-lan":
        if args.origem_simulada == "198.51.100.10":
            partes = args.destino.split(".")
            origem_lan = f"{partes[0]}.{partes[1]}.{partes[2]}.250"
        else:
            origem_lan = args.origem_simulada

        print(f"[*] Verificando previamente se o endereço {origem_lan} está livre na sub-rede local...")
        livre, motivo_verificacao = verificar_ip_livre_na_rede(origem_lan)
        if not livre:
            print(
                f"[ABORTADO POR SEGURANÇA] {motivo_verificacao}\n"
                "Escolha outro endereço comprovadamente livre na sub-rede com --origem-simulada."
            )
            return 1
        print(f"[OK] {motivo_verificacao}")

        transmitir_lote_controlado(
            descricao=f"Demonstração Complementar — Origem Fictícia na Sub-rede Local ({origem_lan})",
            ip_origem=origem_lan,
            ip_destino=args.destino,
            interface=interface,
            quantidade=quantidade,
            intervalo=intervalo,
            aguardar_resposta=False,
        )

    elif args.modo == "rajada-controlada":
        transmitir_rajada_controlada(
            ip_origem_base=args.origem_simulada,
            ip_destino=args.destino,
            interface=interface,
            quantidade=quantidade,
            intervalo=intervalo,
            rotacionar_origem=args.rotacionar_origem,
        )

    print("\n[*] Transmissão concluída na interface local.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
