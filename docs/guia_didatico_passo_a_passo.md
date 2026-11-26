# Guia Técnico Passo a Passo — Ataque, Captura e Mitigação na Camada 3

**Projeto:** Vulnerabilidades na Camada de Rede: Demonstração Prática de IP Spoofing e ICMP Flood  
**Curso:** Bacharelado em Sistemas de Informação — 4º Período (Campus Varginha)

---

## 1. Arquitetura do Experimento

O experimento utiliza duas máquinas Linux conectadas à mesma sub-rede local autorizada (`RFC 1918`):

| Papel | Função Operacional | Ferramentas |
| :--- | :--- | :--- |
| **Máquina Atacante (Emissora)** | Reconhecimento da sub-rede, construção/injeção de pacotes IPv4/ICMP via *Raw Socket* e captura local de saída. | Python 3, Scapy, Wireshark, Nmap, `ping` |
| **Máquina Alvo (Receptora)** | Confirmação independente de chegada dos quadros/pacotes e aplicação de defesas no Kernel. | `tcpdump`, `nftables` (`nft`), `sysctl` (`rp_filter`) |

---

## 2. Roteiro Completo de Execução

### Etapa 0 — Preparar a Máquina Alvo
1. Identifique a interface física ativa e o endereço IPv4 da Máquina Alvo:
   ```bash
   ip -4 -brief addr show scope global
   ```
2. Inicie a captura independente no terminal da Máquina Alvo (substitua `<INTERFACE_ALVO>`, ex.: `ens32` ou `enp2s0`):
   ```bash
   sudo tcpdump -eni <INTERFACE_ALVO> icmp
   ```
   * `-e`: exibe o cabeçalho Ethernet (Camada 2), revelando o endereço físico MAC ao lado do cabeçalho IPv4 (Camada 3);
   * `-n`: mantém endereços numéricos sem resolução DNS;
   * `-i`: seleciona a placa de rede monitorada;
   * `icmp`: filtra apenas mensagens do protocolo ICMP.

---

### Etapa 1 — Reconhecimento e Linha de Base (Máquina Atacante)
Com o **Wireshark** aberto na interface de saída aplicando o filtro `icmp`:

1. **Descoberta de hosts ativos na rede local (`Nmap`):**
   ```bash
   nmap -sn 192.168.1.0/24
   ```
2. **Validação de rota L3 e comunicação legítima (`Ping` ~1 pps):**
   ```bash
   python3 scripts/teste_conectividade.py --alvo <IP_ALVO>
   ```
   * Com o IP de origem verdadeiro, a Máquina Alvo devolve `ICMP Echo Reply (Type 0)` normalmente (`0% packet loss`).

---

### Etapa 2 — Inspeção e Demonstração de IP Spoofing (`RFC 5737`)
1. **Inspeção didática dos cabeçalhos em memória (sem transmitir na rede):**
   ```bash
   python3 scripts/demonstracao_icmp.py --modo inspecao --destino <IP_ALVO>
   ```
2. **Transmissão controlada de 3 pacotes com `Source IP` falsificado (`198.51.100.10`):**
   ```bash
   sudo python3 scripts/demonstracao_icmp.py --modo spoof-doc --destino <IP_ALVO> --quantidade 3 --intervalo 1.0
   ```
   * **Como interpretar a evidência:**
     * No **Wireshark (Máquina Atacante):** comprova-se que o pacote saiu com `Source: 198.51.100.10` e que nenhum `Echo Reply` retornou ao atacante (*Blind Spoofing*).
     * No **`tcpdump -eni` (Máquina Alvo):** comprova-se na mesma linha que o quadro partiu do MAC físico da Máquina Atacante na Camada 2 carregando o `Source IP` forjado `198.51.100.10` na Camada 3.

---

### Etapa 3 — Rajada ICMP Controlada com Rotação de Origem
```bash
sudo python3 scripts/demonstracao_icmp.py --modo rajada-controlada --destino <IP_ALVO> --quantidade 50 --intervalo 0.02 --rotacionar-origem
```
* Utiliza `conf.L3socket` do Scapy para injetar 50 pacotes em sequência rápida, alternando o campo `src` a cada pacote (`198.51.100.10` até `198.51.100.59`).
* Em **Statistics → I/O Graphs** no Wireshark, observa-se o salto abrupto da linha de base (`~1 pps`) para o pico da rajada (`~50 pps` na demonstração curta, ou `~400+ pps` com `--intervalo 0`).

---

### Etapa 4 — Mitigação Prática Contra ICMP Flood com `nftables` (Máquina Alvo)

Para proteger a Máquina Alvo mesmo quando cada pacote declara um `Source IP` diferente, aplica-se *Rate Limiting* global por tipo ICMP no subsistema **Netfilter (`nftables`)** do Kernel Linux:

```bash
# 1. Cria a tabela dual-stack (IPv4/IPv6) chamada 'filter'
sudo nft add table inet filter

# 2. Cria a chain ligada ao gancho 'input' do Kernel com política padrão 'accept' (preserva SSH e demais serviços)
sudo nft 'add chain inet filter input { type filter hook input priority 0 ; policy accept ; }'

# 3. Regra 1 (Token Bucket): aceita até 5 Echo Requests/s com folga inicial (burst) de 10 pacotes
sudo nft add rule inet filter input icmp type echo-request limit rate 5/second burst 10 packets counter accept

# 4. Regra 2 (Barreira): descarta silenciosamente todo Echo Request que exceder o limite acima
sudo nft add rule inet filter input icmp type echo-request counter drop
```

#### Verificando o bloqueio em tempo real:
Após disparar uma rajada de teste contra a Máquina Alvo protegida, consulte os contadores do Kernel:
```bash
sudo nft list chain inet filter input
```
* **Observação importante sobre o `tcpdump`:** Como o `tcpdump` captura os quadros na interface de rede (`AF_PACKET`) **antes** do gancho `input` do Netfilter, todos os `Echo Request` continuarão visíveis chegando no `tcpdump`, mas os contadores do `nftables` comprovarão que o excesso recebeu `drop` antes de consumir CPU gerando `Echo Reply`.

#### Removendo as regras ao final do teste:
```bash
sudo nft delete table inet filter
```

---

### Etapa 5 — Defesa Contra IP Spoofing (`BCP 38` e `uRPF`)

1. **Network Ingress / Egress Filtering (`BCP 38` / `RFC 2827`):** configurado em roteadores de borda e switches L3 para descartar pacotes cujo `Source IP` não pertença ao prefixo da interface de origem.
2. **Unicast Reverse Path Forwarding (`rp_filter`) no Linux:**
   ```bash
   sudo sysctl -w net.ipv4.conf.all.rp_filter=1
   ```
   No modo estrito (`1`), o Kernel consulta sua tabela de roteamento ao receber um pacote: se a rota de saída para alcançar aquele `Source IP` não for a mesma interface por onde o pacote entrou, o pacote é descartado imediatamente como *Martian packet*.

---

### Etapa 6 — Análise Estatística Offline (`analise_pcap.py`)

```bash
python3 scripts/analise_pcap.py capturas/02_captura_real_wireshark.pcapng
```
O analisador classifica os achados em 4 categorias metodológicas:
1. **`[EVIDÊNCIA OBSERVADA]`**: contagem exata de protocolos, tipos ICMP, TTLs e pareamento `(src, dst, id, seq)`.
2. **`[INDÍCIO DE POSSÍVEL SPOOFING]`**: requisições sem resposta pareada e múltiplos endereços IPv4 originados do mesmo MAC físico.
3. **`[ALERTA DE ANOMALIA VOLUMÉTRICA]`**: heurística didática de IDS para taxas `>= 10 pps` ou intervalos `Δt <= 100 ms`.
4. **`[RESULTADO INCONCLUSIVO ISOLADAMENTE]`**: lembrete de que a captura local no emissor comprova o envio e deve ser cruzada com o `tcpdump -eni` na Máquina Alvo.
