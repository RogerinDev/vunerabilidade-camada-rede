#!/usr/bin/env python3
"""
analise_pcap.py — Analisador Estatístico de Capturas (.pcap / .pcapng) para a Camada 3 (OSI)

Objetivo acadêmico:
Ler arquivos de captura (.pcap ou .pcapng) sem transmitir pacotes na rede e apresentar:
  1. Natureza do arquivo (Distinção entre PCAP Simulado/Didático vs. Captura de Rede);
  2. Métricas globais e por Fluxo/Fase (separando Linha de Base Legítima vs. Tráfego
     Spoofado/Rajada para que pausas humanas na apresentação não diluam o cálculo de pps);
  3. Taxa de pico em janela móvel de 1 segundo (Peak PPS) e intervalo médio (Delta t);
  4. Avaliação técnica rigorosa classificada em:
     - [EVIDÊNCIA OBSERVADA]
     - [INDÍCIO DE POSSÍVEL SPOOFING]
     - [ALERTA DE LIMIAR DE TAXA / IDS THRESHOLD]
     - [RESULTADO INCONCLUSIVO ISOLADAMENTE — REQUER CONFIRMAÇÃO NO ALVO]
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import ipaddress
from pathlib import Path
import sys

from scapy.all import ARP, Ether, ICMP, IP, TCP, UDP, rdpcap

MAPA_TIPOS_ICMP: dict[int, str] = {
    0: "Echo Reply (Resposta de Ping)",
    3: "Destination Unreachable (Destino Inalcançável)",
    5: "Redirect (Redirecionamento de Rota L3)",
    8: "Echo Request (Pedido de Ping)",
    11: "Time Exceeded (TTL Expirado em Trânsito)",
}

MAPA_PROTOCOLOS_IP: dict[int, str] = {
    1: "ICMP (Camada 3)",
    6: "TCP (Camada 4)",
    17: "UDP (Camada 4)",
}

MACS_DOCUMENTACAO_SIMULADOS = {
    "00:00:5e:00:53:01",
    "00:00:5e:00:53:02",
    "02:aa:bb:cc:dd:ee",
    "02:11:22:33:44:55",
}

REDES_DOCUMENTACAO_RFC5737 = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)

LIMIAR_PAUSA_HUMANA_SEG = 2.5
LIMIAR_IDS_PPS = 10.0
LIMIAR_IDS_DELTA_MS = 100.0


def pertence_rfc5737(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
        return any(ip_obj in rede for rede in REDES_DOCUMENTACAO_RFC5737)
    except ValueError:
        return False


def calcular_pico_pps_janela_1s(tempos_ordenados: list[float]) -> int:
    """Calcula a quantidade máxima de pacotes observada dentro de qualquer janela móvel de 1.0s."""
    if not tempos_ordenados:
        return 0
    max_na_janela = 1
    inicio = 0
    for fim, t_fim in enumerate(tempos_ordenados):
        while t_fim - tempos_ordenados[inicio] > 1.0:
            inicio += 1
        qtd = fim - inicio + 1
        if qtd > max_na_janela:
            max_na_janela = qtd
    return max_na_janela


def calcular_metricas_fase_ativa(tempos: list[float]) -> tuple[float, float, float, int]:
    """
    Calcula (duracao_ativa_s, pps_ativo, delta_t_medio_ms, peak_pps_1s) ignorando lacunas
    de pausa humana (> LIMIAR_PAUSA_HUMANA_SEG) entre comandos diferentes na apresentação.
    """
    if not tempos:
        return 0.0, 0.0, 0.0, 0
    ts = sorted(tempos)
    peak_1s = calcular_pico_pps_janela_1s(ts)
    if len(ts) == 1:
        return 0.0, 1.0, 0.0, 1

    deltas_ativos = [
        ts[i] - ts[i - 1]
        for i in range(1, len(ts))
        if (ts[i] - ts[i - 1]) <= LIMIAR_PAUSA_HUMANA_SEG
    ]
    if not deltas_ativos:
        # Todos os pacotes foram espaçados por mais que o limiar (ex: envios manuais lentos)
        deltas_ativos = [ts[i] - ts[i - 1] for i in range(1, len(ts))]

    duracao_ativa = sum(deltas_ativos)
    delta_medio_ms = (duracao_ativa / len(deltas_ativos)) * 1000.0
    pps_ativo = (len(deltas_ativos) / duracao_ativa) if duracao_ativa > 0.0001 else float(len(ts))
    return duracao_ativa, pps_ativo, delta_medio_ms, peak_1s


def segmentar_fases_echo_request(
    eventos_req: list[tuple[float, str, str]]
) -> list[list[tuple[float, str, str]]]:
    """Divide a linha do tempo de Echo Requests em fases separadas por pausas > 2.5s."""
    if not eventos_req:
        return []
    ordenados = sorted(eventos_req, key=lambda x: x[0])
    fases: list[list[tuple[float, str, str]]] = [[ordenados[0]]]
    for ev in ordenados[1:]:
        if ev[0] - fases[-1][-1][0] > LIMIAR_PAUSA_HUMANA_SEG:
            fases.append([ev])
        else:
            fases[-1].append(ev)
    return fases


def analisar_arquivo_pcap(caminho: Path) -> int:
    if not caminho.exists():
        print(f"[ERRO] Arquivo de captura não encontrado: {caminho}")
        return 1

    try:
        pacotes = rdpcap(str(caminho))
    except Exception as exc:
        print(f"[ERRO] Não foi possível ler o arquivo '{caminho}': {exc}")
        return 1

    total_pacotes = len(pacotes)
    if total_pacotes == 0:
        print(f"[AVISO] O arquivo '{caminho}' não contém pacotes.")
        return 0

    timestamps: list[float] = []
    tamanhos_bytes: list[int] = []
    contagem_protocolos: Counter[str] = Counter()
    fluxos_ip: Counter[tuple[str, str]] = Counter()
    tempos_por_fluxo: defaultdict[tuple[str, str], list[float]] = defaultdict(list)
    ttls_por_fluxo: defaultdict[tuple[str, str], set[int]] = defaultdict(set)
    contagem_icmp: Counter[tuple[int, int]] = Counter()
    requests_por_origem: Counter[str] = Counter()
    replies_para_destino: Counter[str] = Counter()
    chaves_echo_request: Counter[tuple[str, str, int, int]] = Counter()
    chaves_echo_reply: Counter[tuple[str, str, int, int]] = Counter()
    registros_echo_request: list[tuple[float, str, str, int, int]] = []
    ips_por_mac_origem: defaultdict[str, set[str]] = defaultdict(set)
    macs_vistos: set[str] = set()
    arp_requests_vistos: int = 0
    arp_who_has_pares: Counter[tuple[str, str]] = Counter()

    for pkt in pacotes:
        ts_pkt = float(pkt.time)
        timestamps.append(ts_pkt)
        tamanhos_bytes.append(len(pkt))

        if pkt.haslayer(Ether):
            mac_s = str(pkt[Ether].src).lower()
            mac_d = str(pkt[Ether].dst).lower()
            macs_vistos.update((mac_s, mac_d))

        if pkt.haslayer(IP):
            camada_ip = pkt[IP]
            src_ip = str(camada_ip.src)
            dst_ip = str(camada_ip.dst)
            proto_num = int(camada_ip.proto)
            nome_proto = MAPA_PROTOCOLOS_IP.get(proto_num, f"IP Proto {proto_num}")
            contagem_protocolos[nome_proto] += 1

            fluxo = (src_ip, dst_ip)
            fluxos_ip[fluxo] += 1
            tempos_por_fluxo[fluxo].append(ts_pkt)
            ttls_por_fluxo[fluxo].add(int(camada_ip.ttl))

            if pkt.haslayer(Ether):
                mac_src = str(pkt[Ether].src).lower()
                if mac_src and mac_src != "00:00:00:00:00:00":
                    ips_por_mac_origem[mac_src].add(src_ip)

            if pkt.haslayer(ICMP):
                camada_icmp = pkt[ICMP]
                tipo = int(camada_icmp.type)
                codigo = int(camada_icmp.code)
                icmp_id = int(getattr(camada_icmp, "id", 0) or 0)
                icmp_seq = int(getattr(camada_icmp, "seq", 0) or 0)
                contagem_icmp[(tipo, codigo)] += 1
                if tipo == 8:
                    requests_por_origem[src_ip] += 1
                    chaves_echo_request[(src_ip, dst_ip, icmp_id, icmp_seq)] += 1
                    registros_echo_request.append((ts_pkt, src_ip, dst_ip, icmp_id, icmp_seq))
                elif tipo == 0:
                    replies_para_destino[dst_ip] += 1
                    chaves_echo_reply[(dst_ip, src_ip, icmp_id, icmp_seq)] += 1
        elif pkt.haslayer(ARP):
            contagem_protocolos["ARP (Camada 2)"] += 1
            if int(pkt[ARP].op) == 1:
                arp_requests_vistos += 1
                psrc = str(pkt[ARP].psrc)
                pdst = str(pkt[ARP].pdst)
                arp_who_has_pares[(psrc, pdst)] += 1
        elif pkt.haslayer(TCP) or pkt.haslayer(UDP):
            contagem_protocolos["Outro Transporte"] += 1
        else:
            contagem_protocolos["Outros Quadros"] += 1

    nome_lower = caminho.name.lower()
    eh_simulado = (
        any(termo in nome_lower for termo in ("simulado", "didatico", "exemplo"))
        or bool(macs_vistos & MACS_DOCUMENTACAO_SIMULADOS)
    )

    timestamps.sort()
    duracao_seg = max(0.0, timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.0
    frequencia_pps = (total_pacotes / duracao_seg) if duracao_seg > 0.0001 else float(total_pacotes)
    intervalos_ms = [
        (timestamps[i] - timestamps[i - 1]) * 1000.0 for i in range(1, len(timestamps))
    ]
    intervalo_medio_ms = (sum(intervalos_ms) / len(intervalos_ms)) if intervalos_ms else 0.0
    total_bytes = sum(tamanhos_bytes)
    tamanho_medio = total_bytes / total_pacotes

    # Separação dos Echo Requests em Linha de Base Legítima vs. Sem Retorno / RFC 5737
    tempos_req_legitimos: list[float] = []
    tempos_req_spoof_ou_rajada: list[float] = []
    ips_rfc5737_vistos: set[str] = set()

    for ts_r, s_ip, d_ip, i_id, i_seq in registros_echo_request:
        if pertence_rfc5737(s_ip):
            ips_rfc5737_vistos.add(s_ip)
        tem_reply = chaves_echo_reply.get((s_ip, d_ip, i_id, i_seq), 0) > 0
        if tem_reply and not pertence_rfc5737(s_ip):
            tempos_req_legitimos.append(ts_r)
        else:
            tempos_req_spoof_ou_rajada.append(ts_r)

    print("==============================================================================")
    print(" RELATÓRIO ESTATÍSTICO DE CAPTURA — CAMADA 3 (MODELO OSI)")
    print("==============================================================================")
    if eh_simulado:
        print(" [CLASSIFICAÇÃO DO ARQUIVO]: PCAP DIDÁTICO / SIMULADO")
        print(" AVISO: Este arquivo contém quadros sintéticos de estudo e NÃO deve ser")
        print(" utilizado como comprovação experimental de tráfego real transmitido na rede.")
        print("------------------------------------------------------------------------------")
    else:
        print(" [CLASSIFICAÇÃO DO ARQUIVO]: CAPTURA DE TRÁFEGO (.pcap / .pcapng)")
        print("------------------------------------------------------------------------------")

    print(f" Arquivo analisado        : {caminho}")
    print(f" Total de pacotes         : {total_pacotes}")
    print(f" Volume total capturado   : {total_bytes} bytes (média: {tamanho_medio:.1f} bytes/pacote)")
    print(f" Janela total do arquivo  : {duracao_seg:.4f} s (inclui eventuais pausas entre comandos)")
    print(f" Média global (bruta)     : {frequencia_pps:.2f} pps | Delta t global: {intervalo_medio_ms:.2f} ms")

    print("\n------------------------------------------------------------------------------")
    print(" 1. DISTRIBUIÇÃO POR PROTOCOLO [EVIDÊNCIA OBSERVADA]")
    print("------------------------------------------------------------------------------")
    for proto, qtd in contagem_protocolos.most_common():
        perc = (qtd / total_pacotes) * 100.0
        print(f"  - {proto:<28} : {qtd:>5} pacote(s) ({perc:5.1f}%)")

    print("\n------------------------------------------------------------------------------")
    print(" 2. FLUXOS DE CAMADA 3 E MÉTRICAS POR FASE ATIVA [ANTES vs. DEPOIS]")
    print("------------------------------------------------------------------------------")
    if fluxos_ip:
        fluxos_principais = fluxos_ip.most_common(12)
        print(
            f"  {'IP Origem (src)':<17} {'IP Destino (dst)':<17} {'Pkts':>5}  "
            f"{'Taxa Ativa':>11}  {'Delta t':>10}  {'TTLs'}"
        )
        print(f"  {'-' * 17} {'-' * 17} {'-' * 5}  {'-' * 11}  {'-' * 10}  {'-' * 8}")
        for (src, dst), qtd in fluxos_principais:
            _, pps_flx, dt_flx, _ = calcular_metricas_fase_ativa(tempos_por_fluxo[(src, dst)])
            ttls_str = ",".join(str(t) for t in sorted(ttls_por_fluxo[(src, dst)]))
            pps_txt = f"{pps_flx:6.2f} pps" if qtd > 1 else "  único   "
            dt_txt = f"{dt_flx:7.2f} ms" if qtd > 1 else "     -    "
            print(f"  {src:<17} {dst:<17} {qtd:>5}  {pps_txt:>11}  {dt_txt:>10}  TTL={ttls_str}")
        if len(fluxos_ip) > 12:
            restantes = len(fluxos_ip) - 12
            print(
                f"  ... (+ {restantes} fluxos adicionais omitidos na tabela — ex.: rotação dinâmica de IPs)"
            )
    else:
        print("  (Nenhum pacote IPv4 encontrado na captura)")

    # Comparativo Antes vs. Depois (Linha de Base vs. Spoofing/Rajada)
    dur_leg, pps_leg, dt_leg, peak_leg = calcular_metricas_fase_ativa(tempos_req_legitimos)
    dur_spf, pps_spf, dt_spf, peak_spf = calcular_metricas_fase_ativa(tempos_req_spoof_ou_rajada)

    pps_rajada_max = pps_spf
    dt_rajada_min = dt_spf

    if registros_echo_request:
        fases = segmentar_fases_echo_request(
            [(t, s, d) for (t, s, d, _, _) in registros_echo_request]
        )
        for fase in fases:
            if len(fase) >= 5:
                tf = [ev[0] for ev in fase]
                df = max(0.0, tf[-1] - tf[0])
                if df > 0.0001:
                    pf = (len(tf) - 1) / df
                    dtf = (df / (len(tf) - 1)) * 1000.0
                    if pf > pps_rajada_max:
                        pps_rajada_max = pf
                        dt_rajada_min = dtf
        print("\n  [Comparativo de Taxa por Grupo — Sem Diluição por Pausas Ociosas]:")
        if tempos_req_legitimos:
            print(
                f"  * Linha de Base Legítima (com Reply) : {len(tempos_req_legitimos):>3} req | "
                f"Duração ativa: {dur_leg:5.2f}s | Taxa: {pps_leg:6.2f} pps | "
                f"Delta t: {dt_leg:7.2f} ms | Pico (1s): {peak_leg} pps"
            )
        else:
            print("  * Linha de Base Legítima (com Reply) : (Nenhum Echo Request pareado nesta captura)")

        if tempos_req_spoof_ou_rajada:
            print(
                f"  * Tráfego Spoofing / Rajada (s/ Reply): {len(tempos_req_spoof_ou_rajada):>3} req | "
                f"Duração ativa: {dur_spf:5.2f}s | Taxa: {pps_spf:6.2f} pps | "
                f"Delta t: {dt_spf:7.2f} ms | Pico (1s): {peak_spf} pps"
            )
        else:
            print("  * Tráfego Spoofing / Rajada (s/ Reply): (Nenhum Echo Request sem resposta nesta captura)")

        fases = segmentar_fases_echo_request(
            [(t, s, d) for (t, s, d, _, _) in registros_echo_request]
        )
        if len(fases) > 1:
            print("\n  [Fases Temporais de Echo Request Detectadas na Captura]:")
            for idx_f, fase in enumerate(fases, start=1):
                tempos_f = [ev[0] for ev in fase]
                ips_f = {ev[1] for ev in fase}
                dur_f = max(0.0, tempos_f[-1] - tempos_f[0]) if len(tempos_f) > 1 else 0.0
                pps_f = ((len(tempos_f) - 1) / dur_f) if dur_f > 0.0001 else float(len(tempos_f))
                dt_f = (dur_f / (len(tempos_f) - 1) * 1000.0) if len(tempos_f) > 1 else 0.0
                resumo_ip = (
                    next(iter(ips_f))
                    if len(ips_f) == 1
                    else f"{len(ips_f)} IPs distintos (rotação)"
                )
                print(
                    f"    - Fase {idx_f}: {len(fase):>3} pacote(s) | Origem: {resumo_ip:<26} | "
                    f"Taxa: {pps_f:6.2f} pps | Delta t: {dt_f:7.2f} ms"
                )

    print("\n------------------------------------------------------------------------------")
    print(" 3. CONTAGEM DE MENSAGENS ICMP (TIPOS E CÓDIGOS) [EVIDÊNCIA OBSERVADA]")
    print("------------------------------------------------------------------------------")
    if contagem_icmp:
        for (tipo, codigo), qtd in sorted(contagem_icmp.items()):
            desc = MAPA_TIPOS_ICMP.get(tipo, "Outro Tipo ICMP")
            print(f"  - Type {tipo:>2}, Code {codigo:>2} [{desc:<40}] : {qtd:>4} pacote(s)")
    else:
        print("  (Nenhum pacote ICMP encontrado na captura)")

    print("\n------------------------------------------------------------------------------")
    print(" 4. AVALIAÇÃO TÉCNICA DA CAPTURA (EVIDÊNCIAS, INDÍCIOS E DETECÇÃO IDS)")
    print("------------------------------------------------------------------------------")

    if requests_por_origem:
        print(
            "  A) Pareamento Exato Echo Request (Tipo 8) vs. Echo Reply (Tipo 0)\n"
            "     [Critério: correspondência por (src_ip, dst_ip, icmp_id, icmp_seq)]:"
        )
        origens_ordenadas = requests_por_origem.most_common()
        for ip_src, qtd_req in origens_ordenadas[:8]:
            qtd_rep_total = replies_para_destino.get(ip_src, 0)
            pares_exatos = sum(
                min(qtd_chave, chaves_echo_reply.get(chave, 0))
                for chave, qtd_chave in chaves_echo_request.items()
                if chave[0] == ip_src
            )
            if pares_exatos == qtd_req:
                classificacao = (
                    "[EVIDÊNCIA OBSERVADA] Fluxo bidirecional pareado por (IP, ID, Seq)."
                )
            elif pares_exatos == 0 and qtd_rep_total == 0:
                classificacao = (
                    "[INDÍCIO DE POSSÍVEL SPOOFING / ASSIMETRIA] Echo Request sem Reply correspondente."
                )
            else:
                classificacao = (
                    f"[RESULTADO PARCIAL] {pares_exatos}/{qtd_req} pares exatos confirmados."
                )
            print(
                f"     * Origem {ip_src:<16}: {qtd_req:>3} Request(s) | "
                f"{pares_exatos:>3} Reply(s) pareado(s) -> {classificacao}"
            )
        if len(origens_ordenadas) > 8:
            print(
                f"     * ... (+ {len(origens_ordenadas) - 8} endereços de origem adicionais sem Reply "
                "registrados na rajada com rotação de IP)"
            )

    macs_multiplos_ips = {
        mac: ips for mac, ips in ips_por_mac_origem.items() if len(ips) > 1
    }
    if macs_multiplos_ips and not eh_simulado:
        print("\n  B) Associação entre Endereço MAC (Camada 2) e IPs de Origem (Camada 3):")
        for mac, ips in macs_multiplos_ips.items():
            ips_ord = sorted(ips)
            amostra = ", ".join(ips_ord[:6])
            if len(ips_ord) > 6:
                amostra += f" ... (total de {len(ips_ord)} IPs distintos)"
            print(f"     * MAC {mac} -> IPs de origem observados: {amostra}")
            print(
                "       -> [INDÍCIO DE POSSÍVEL SPOOFING]: Múltiplos endereços IPv4 de origem "
                "partindo do mesmo endereço físico MAC na Camada 2."
            )

    if arp_requests_vistos > 0:
        print(f"\n  C) Solicitações ARP 'Who-Has' observadas na Camada 2 ({arp_requests_vistos} total):")
        for (psrc, pdst), qtd_arp in arp_who_has_pares.most_common(5):
            correlacao = (
                " [CORRELACIONADO COM ORIGEM ICMP DECLARADA NESTA CAPTURA]"
                if pdst in requests_por_origem
                else ""
            )
            print(f"     * ARP Request: '{psrc}' perguntou quem tem '{pdst}' ({qtd_arp}x){correlacao}")

    print(
        "\n  D) Critério Metodológico de Comprovação [IMPORTANTE PARA A APRESENTAÇÃO]:\n"
        "     -> [RESULTADO INCONCLUSIVO SE AVALIADO APENAS NO EMISSOR]: O PCAP local comprova o envio.\n"
        "     -> Para comprovar a recepção no alvo, cruze: (1) IP/MAC real da Máquina Atacante, (2) Source IP\n"
        "        declarado no cabeçalho e (3) captura independente 'tcpdump -eni' na Máquina Alvo."
    )

    # Item E: Simulação de Regra de IDS / Avaliação de Limiar de Disponibilidade
    todos_tempos_req = [r[0] for r in registros_echo_request]
    pico_req_1s = calcular_pico_pps_janela_1s(sorted(todos_tempos_req))
    detectou_rajada = (
        pico_req_1s >= LIMIAR_IDS_PPS
        or (len(tempos_req_spoof_ou_rajada) >= 5 and 0.0 < dt_rajada_min <= LIMIAR_IDS_DELTA_MS)
        or len(ips_rfc5737_vistos) >= 5
    )

    print("\n  E) Avaliação de Limiar de Disponibilidade / Regra de Detecção (IDS Threshold):")
    if detectou_rajada:
        print(
            "     -> [ALERTA DE ANOMALIA VOLUMÉTRICA / RAJADA ICMP DETECTADA]:\n"
            f"        * Pico medido em janela de 1s : {pico_req_1s} pacotes/segundo "
            f"(Limiar IDS configurado: >= {LIMIAR_IDS_PPS:.0f} pps)\n"
            f"        * Intervalo médio na rajada   : {dt_rajada_min:.2f} ms entre pacotes "
            f"(Limiar IDS: <= {LIMIAR_IDS_DELTA_MS:.0f} ms)\n"
            f"        * Origens RFC 5737 distintas  : {len(ips_rfc5737_vistos)} endereço(s) diferente(s)"
        )
        if pps_leg > 0.0 and pps_rajada_max > 0.0:
            fator = pps_rajada_max / pps_leg
            print(
                f"        * Razão de Amplificação       : A frequência ativa da rajada ({pps_rajada_max:.1f} pps) "
                f"foi {fator:.1f}x superior à linha de base do ping normal ({pps_leg:.2f} pps)."
            )
        if len(ips_rfc5737_vistos) > 1:
            print(
                "        * Implicação de Defesa        : Como o IP de origem muda a cada pacote, regras "
                "de firewall por IP individual falham; exige-se BCP 38 / rp_filter=1 e Rate Limiting ICMP."
            )
    else:
        print(
            f"     -> [DENTRO DA NORMALIDADE]: Pico máximo de Echo Request foi {pico_req_1s} pps "
            f"(abaixo do limiar de alerta de {LIMIAR_IDS_PPS:.0f} pps)."
        )

    print("==============================================================================")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analisa arquivos .pcap / .pcapng e gera relatório estatístico da Camada 3."
    )
    parser.add_argument(
        "arquivo",
        type=Path,
        help="Caminho para o arquivo .pcap ou .pcapng (ex: capturas/02_captura_real_wireshark.pcapng)",
    )
    args = parser.parse_args()
    return analisar_arquivo_pcap(args.arquivo)


if __name__ == "__main__":
    sys.exit(main())
