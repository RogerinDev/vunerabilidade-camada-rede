# Scripts Python (`scripts/`)

Ferramentas desenvolvidas em **Python 3 + Scapy** para diagnóstico de conectividade, construção/transmissão controlada de pacotes na Camada 3 e análise estatística de arquivos `.pcap` / `.pcapng`.

---

## 1. `teste_conectividade.py` — Diagnóstico e Linha de Base
Verifica a instalação das ferramentas (`scapy`, `ping`, `nmap`, `tcpdump`, `wireshark`), descobre automaticamente a rota de Camada 3 (`ip -4 route get`), exibe o endereço físico MAC local e executa um teste controlado de `ping` para estabelecer a linha de base legítima.

```bash
python3 scripts/teste_conectividade.py --alvo 192.168.1.15 --quantidade 4
```

---

## 2. `demonstracao_icmp.py` — Inspeção, IP Spoofing e Rajada Controlada
Constrói pacotes `IP(src, dst) / ICMP(type=8)` usando *Raw Sockets* na Camada 3.

### Modos disponíveis (`--modo`):
| Modo | Requer `sudo`? | Descrição |
| :--- | :---: | :--- |
| `inspecao` | Não | Exibe no terminal a anatomia completa dos cabeçalhos IPv4 (20 B) e ICMP (8 B) sem transmitir pacotes na rede. |
| `normal` | Sim | Envia pacotes `Echo Request` com o IP real da Máquina Atacante e aguarda `Echo Reply` (`sr1`). |
| `spoof-doc` | Sim | **Demonstração principal de IP Spoofing:** envia pacotes com `Source IP` reservado pela `RFC 5737` (`198.51.100.10`). |
| `spoof-lan` | Sim | **Demonstração complementar:** verifica previamente via `ping` + `ip neigh` se um IP da sub-rede está livre antes de transmitir. |
| `rajada-controlada` | Sim | **Demonstração de ICMP Flood controlado:** transmite lote finito via `conf.L3socket` com opção `--rotacionar-origem` (`198.51.100.10..200`). |

### Exemplos:
```bash
# Inspeção didática offline
python3 scripts/demonstracao_icmp.py --modo inspecao --destino 192.168.1.15

# IP Spoofing controlado (3 pacotes, 1 por segundo)
sudo python3 scripts/demonstracao_icmp.py --modo spoof-doc --destino 192.168.1.15 --quantidade 3 --intervalo 1.0

# Rajada controlada de 50 pacotes com rotação de origem (~50 pps)
sudo python3 scripts/demonstracao_icmp.py --modo rajada-controlada --destino 192.168.1.15 --quantidade 50 --intervalo 0.02 --rotacionar-origem
```

### Travas de segurança implementadas no código:
* Rejeita qualquer `--destino` fora das redes privadas `RFC 1918` (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) ou loopback.
* Restringe o modo `rajada-controlada` exclusivamente a endereços de origem de documentação `RFC 5737` e lotes finitos (sem loops infinitos).

---

## 3. `analise_pcap.py` — Analisador Estatístico e Heurística de IDS
Lê capturas `.pcap` ou `.pcapng` offline, separa automaticamente pausas humanas entre comandos (`> 2,5 s`) para não diluir o cálculo de taxa (`pps`), pareia `Echo Request` com `Echo Reply` por `(src, dst, id, seq)`, identifica múltiplos IPs originados do mesmo MAC físico e avalia limiares volumétricos (`>= 10 pps` ou `Δt <= 100 ms`).

```bash
python3 scripts/analise_pcap.py capturas/02_captura_real_wireshark.pcapng
```
