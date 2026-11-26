# Vulnerabilidades na Camada de Rede (L3 OSI): IP Spoofing e ICMP Flood

![Camada 3 OSI](https://img.shields.io/badge/Modelo_OSI-Camada_3_(Rede)-0284c7)
![Protocolos](https://img.shields.io/badge/Protocolos-IPv4_%7C_ICMP-e11d48)
![Python](https://img.shields.io/badge/Python-3.10%2B_%7C_Scapy-059669)
![Defesa](https://img.shields.io/badge/Mitiga%C3%A7%C3%A3o-nftables_%7C_uRPF_%7C_BCP_38-4f46e5)

Projeto prático acadêmico desenvolvido para a disciplina de **Laboratório de Redes / Redes de Computadores** do curso de **Bacharelado em Sistemas de Informação (4º Período — Campus Varginha)**.

O repositório investiga, demonstra em ambiente controlado e mitiga duas vulnerabilidades clássicas da **Camada 3 do Modelo OSI**:
1. **IP Spoofing (Falsificação de Identidade L3):** exploração da ausência de autenticação criptográfica nativa do campo `Source IP` no cabeçalho IPv4 (`RFC 791`).
2. **ICMP Flood (Sobrecarga Volumétrica):** disparo em alta frequência de mensagens `ICMP Echo Request (Type 8)` (`RFC 792`) combinado com rotação dinâmica de endereços de origem (`RFC 5737`), além da mitigação prática no Kernel Linux via `nftables` e `rp_filter`.

---

## Integrantes da Equipe

* **Gabriel Domingueti Gonçalves**
* **Nycolas Samuel da Silva Ferreira**
* **Samuel Bissoni Cézar**
* **Rogério Otávio Filho**

---

## Sumário

1. [Escopo Técnico e Rigor Metodológico](#1-escopo-técnico-e-rigor-metodológico)
2. [Estrutura do Repositório](#2-estrutura-do-repositório)
3. [Pré-requisitos e Instalação](#3-pré-requisitos-e-instalação)
4. [Execução Passo a Passo no Laboratório](#4-execução-passo-a-passo-no-laboratório)
5. [Mitigação e Defesa na Prática (`nftables` e `uRPF`)](#5-mitigação-e-defesa-na-prática-nftables-e-urpf)
6. [Resultados Experimentais Obtidos](#6-resultados-experimentais-obtidos)
7. [Apresentação Interativa em HTML](#7-apresentação-interativa-em-html)
8. [Referências Normativas (RFCs)](#8-referências-normativas-rfcs)
9. [Aviso Ético](#9-aviso-ético)

---

## 1. Escopo Técnico e Rigor Metodológico

* **Causa raiz arquitetural:** O protocolo IPv4 transporta o endereço de origem (`Source IP`, 32 bits), mas os roteadores decidem o encaminhamento olhando por padrão apenas para o destino (`Destination IP`), sem validar criptograficamente se o remetente é o titular do IP declarado.
* **Emissão vs. Recepção:** Capturar pacotes apenas na **Máquina Atacante** (Wireshark) comprova somente a montagem e injeção local na placa de rede. A confirmação experimental de chegada exige captura independente na **Máquina Alvo** (`sudo tcpdump -eni <INTERFACE> icmp`), correlacionando o endereço físico MAC (Camada 2) ao `Source IP` forjado (Camada 3).
* **Blind Spoofing:** Quando o `Source IP` é falsificado para a faixa de documentação `198.51.100.0/24` (`RFC 5737`), eventuais pacotes `Echo Reply (Type 0)` são desviados para o endereço declarado ou descartados por filtros de rota reversa (`rp_filter`), nunca retornando à Máquina Atacante.

---

## 2. Estrutura do Repositório

```text
.
├── README.md                                  # Visão geral, instruções de execução, defesas e resultados
├── .gitignore                                 # Regras de exclusão para cache Python e capturas temporárias
├── scripts/
│   ├── README.md                              # Referência detalhada de argumentos CLI e travas de segurança
│   ├── teste_conectividade.py                 # Diagnóstico de ambiente, rota L3 e linha de base (Ping normal)
│   ├── demonstracao_icmp.py                   # Montagem, inspeção e envio controlado (IP Spoofing & ICMP Flood)
│   ├── analise_pcap.py                        # Analisador estatístico de capturas (.pcap/.pcapng) e heurística IDS
│   └── requisitos.txt                         # Dependências Python (Scapy) e pacotes de sistema Linux
├── slides/
│   ├── README.md                              # Guia de navegação e recursos visuais dos slides
│   └── apresentacao_camada3.html              # Apresentação interativa autocontida (9 slides + simuladores)
├── capturas/
│   ├── README.md                              # Diferença entre captura real e simulada + filtros Wireshark
│   ├── 02_captura_real_wireshark.pcapng       # Captura real do experimento (10.000 pacotes ICMP Spoofing/Flood)
│   └── pcap_simulado_didatico.pcap            # Captura sintética (RFC 7042) apenas para teste offline
└── docs/
    ├── README.md                              # Índice do material técnico e acadêmico complementar
    ├── guia_didatico_passo_a_passo.md         # Manual completo de execução e explicação linha por linha
    ├── guia_didatico_camada3.pdf              # Guia didático diagramado em PDF
    ├── sintese_tecnica_equipe.pdf             # Síntese técnica acadêmica dos experimentos e resultados
    └── questoes_revisao_camada3.pdf           # Questões conceituais comentadas sobre Camada 3 e defesas
```

---

## 3. Pré-requisitos e Instalação

A criação de pacotes IPv4 customizados com **Raw Sockets** (`CAP_NET_RAW`) exige execução com `sudo` no Linux. Recomenda-se instalar os pacotes diretamente pelo gerenciador da distribuição:

### Arch Linux / CachyOS
```bash
sudo pacman -S --needed python-scapy wireshark-qt tcpdump nmap nftables
```

### Ubuntu / Debian
```bash
sudo apt update && sudo apt install -y python3-scapy wireshark tcpdump nmap nftables
```

### Ambiente Virtual Python (Opcional)
```bash
pip install -r scripts/requisitos.txt
```

---

## 4. Execução Passo a Passo no Laboratório

Substitua `<IP_ALVO>` (ex.: `192.168.1.15` ou `192.168.1.117`), `<REDE_LOCAL>` (ex.: `192.168.1.0/24`) e `<INTERFACE_ALVO>` (ex.: `ens32` ou `enp2s0`) pelos dados reais da bancada.

### Passo 0 — Na Máquina Alvo (Monitoramento Independente)
Descubra a interface ativa e mantenha o `tcpdump` aberto exibindo os cabeçalhos de Camada 2 (`-e`) e Camada 3:
```bash
ip -4 -brief addr show scope global
sudo tcpdump -eni <INTERFACE_ALVO> icmp
```

### Passo 1 — Na Máquina Atacante: Reconhecimento e Linha de Base
```bash
# 1. Descoberta leve de hosts ativos na sub-rede local
nmap -sn <REDE_LOCAL>

# 2. Diagnóstico de ferramentas, rota L3 e Ping legítimo (~1 pps)
python3 scripts/teste_conectividade.py --alvo <IP_ALVO>
```

### Passo 2 — Inspeção de Cabeçalhos e IP Spoofing Controlado
```bash
# 3. Comparação didática dos cabeçalhos IPv4/ICMP (offline — não transmite pacotes)
python3 scripts/demonstracao_icmp.py --modo inspecao --destino <IP_ALVO>

# 4. Envio controlado de 3 pacotes com Source IP forjado (RFC 5737: 198.51.100.10)
sudo python3 scripts/demonstracao_icmp.py --modo spoof-doc --destino <IP_ALVO> --quantidade 3 --intervalo 1.0
```

### Passo 3 — Rajada ICMP Controlada com Rotação de Origem
```bash
# 5. Rajada curta (50 pacotes a cada 20 ms) rotacionando Source IP (198.51.100.10 .. .59)
sudo python3 scripts/demonstracao_icmp.py --modo rajada-controlada --destino <IP_ALVO> --quantidade 50 --intervalo 0.02 --rotacionar-origem
```

### Passo 4 — Análise Estatística da Captura Real
```bash
# 6. Extrai métricas Antes vs. Depois, Peak PPS, relação MAC x IP e alerta heurístico de IDS
python3 scripts/analise_pcap.py capturas/02_captura_real_wireshark.pcapng
```

---

## 5. Mitigação e Defesa na Prática (`nftables` e `uRPF`)

### 5.1 Defesa Contra ICMP Flood — Rate Limiting no Kernel (`nftables`)
Quando o atacante rotaciona o `Source IP` a cada pacote, bloquear IPs individuais no firewall é ineficaz. A mitigação correta limita globalmente a taxa aceita de `ICMP Echo Request (Type 8)` usando o algoritmo *Token Bucket* no gancho `input` do Netfilter:

```bash
# Executar na Máquina Alvo:
sudo nft add table inet filter
sudo nft 'add chain inet filter input { type filter hook input priority 0 ; policy accept ; }'
sudo nft add rule inet filter input icmp type echo-request limit rate 5/second burst 10 packets counter accept
sudo nft add rule inet filter input icmp type echo-request counter drop

# Auditar pacotes aceitos vs. descartados após o teste:
sudo nft list chain inet filter input

# Remover a tabela ao encerrar o laboratório:
sudo nft delete table inet filter
```

### 5.2 Defesa Contra IP Spoofing — Filtragem de Origem (`BCP 38` e `rp_filter`)
* **Nos Roteadores de Borda (`BCP 38` / `RFC 2827`):** descartar pacotes de saída cujo `Source IP` não pertença à sub-rede alocada à interface de origem.
* **No Host Linux (`Unicast Reverse Path Forwarding — uRPF`):** validar se a rota de retorno para o `Source IP` coincide com a interface física de chegada:
  ```bash
  sudo sysctl -w net.ipv4.conf.all.rp_filter=1
  ```

---

## 6. Resultados Experimentais Obtidos

1. **Validação de IP Spoofing e Rotação de Origem (`capturas/02_captura_real_wireshark.pcapng`):**
   * **Pacotes ICMP Type 8 registrados:** `10.000` solicitações em `25,78 s` ativos.
   * **Taxa sustentada / Pico:** `387,90 pps` médios (`Δt = 2,58 ms`) e pico de **`444 pps`** em janela móvel de 1 segundo.
   * **Diversidade de origens forjadas:** **`191` endereços IPv4 distintos** (`198.51.100.10` a `198.51.100.200`) originados de um único endereço físico MAC na Camada 2.
2. **Eficácia da Mitigação com `nftables` na Máquina Alvo:**
   * Durante o disparo de `10.000` pacotes `ICMP Echo Request`, os contadores do Kernel (`nft list chain inet filter input`) registraram **`132` pacotes aceitos (`accept`)** dentro do limiar de `5/second` (com `burst 10`) e **`9.868` pacotes descartados silenciosamente (`drop`)** — neutralizando **`98,68%`** da sobrecarga antes da geração de respostas `Echo Reply`.

---

## 7. Apresentação Interativa em HTML

O arquivo [`slides/apresentacao_camada3.html`](slides/apresentacao_camada3.html) contém a apresentação visual completa da equipe (zero dependências externas — basta abrir no navegador):

* **Atalhos rápidos:** `←` / `→` ou `Espaço` (navegar), `F` (Tela Cheia limpa para projetor), `T` (alternar Modo Escuro / Modo Claro), `G` (índice rápido de slides).
* **Recursos interativos embutidos:** inspetor de cabeçalho IPv4 (Real vs. Spoofado), simulador de pacotes L2/L3 em tempo real, fluxograma cíclico 2×2 do algoritmo em Scapy e diagramas em grade das barreiras `nftables` e `uRPF / BCP 38`.

---

## 8. Referências Normativas (RFCs)

* **RFC 791** — *Internet Protocol (IPv4)* (J. Postel, 1981)
* **RFC 792** — *Internet Control Message Protocol (ICMP)* (J. Postel, 1981)
* **RFC 1918** — *Address Allocation for Private Internets* (Rekhter et al., 1996)
* **RFC 2827 (BCP 38)** — *Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing* (P. Ferguson & D. Senie, 2000)
* **RFC 3704 (BCP 84)** — *Ingress Filtering for Multihomed Networks / uRPF* (F. Baker & P. Savola, 2004)
* **RFC 5737** — *IPv4 Address Blocks Reserved for Documentation* (J. Arkko et al., 2010)

---

## 9. Aviso Ético

Todo o código deste repositório possui travas explícitas que restringem os destinos exclusivamente às redes privadas internas (`RFC 1918`) e os endereços simulados de rajada às faixas reservadas de documentação (`RFC 5737`). O material destina-se **estritamente ao ensino acadêmico e testes defensivos em ambientes próprios ou expressamente autorizados**.
