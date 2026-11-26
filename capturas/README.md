# Capturas de Pacotes (`capturas/`)

Este diretório reúne os arquivos de captura utilizados para validação estatística no `scripts/analise_pcap.py` e inspeção visual no **Wireshark**. Por rigor metodológico, distinguimos estritamente a **captura real do experimento** do **arquivo sintético para estudo offline**.

---

## Arquivos Incluídos

### 1. `02_captura_real_wireshark.pcapng` *(Captura Real do Experimento)*
* **Natureza:** Tráfego real capturado na interface física durante o teste de **IP Spoofing + ICMP Flood com rotação de origem** e filtrado para conter estritamente os pacotes `ICMP Echo Request (Type 8)` do experimento (sem tráfego de fundo da rede local).
* **Resumo estatístico (`analise_pcap.py`):**
  * `10.000` pacotes `ICMP Type 8` com destino à Máquina Alvo (`192.168.1.15`);
  * `191` endereços IPv4 de origem distintos rotacionados na faixa `RFC 5737` (`198.51.100.10` a `198.51.100.200`) partindo do mesmo endereço MAC de Camada 2;
  * Taxa ativa média de `387,90 pps` (`Δt = 2,58 ms`) e pico de `444 pps` em janela de 1 segundo.

### 2. `pcap_simulado_didatico.pcap` *(Arquivo Sintético para Estudo Offline)*
* **Natureza:** Gerado em memória pelo comando `python3 scripts/demonstracao_icmp.py --modo inspecao --gerar-pcap-simulado capturas/pcap_simulado_didatico.pcap`.
* **Finalidade:** Permitir testar a saída comparativa (*Linha de Base Legítima 1 pps* vs. *Rajada 50 pps*) do `analise_pcap.py` em um único computador desconectado.
* **Identificação explícita:** Utiliza endereços MAC reservados para documentação (`RFC 7042`: `00:00:5e:00:53:01` e `00:00:5e:00:53:02`) e é sinalizado automaticamente pelo analisador como `PCAP DIDÁTICO / SIMULADO`.

---

## Como Analisar

```bash
# Analisar a captura real do experimento
python3 scripts/analise_pcap.py capturas/02_captura_real_wireshark.pcapng

# Analisar o arquivo sintético de estudo
python3 scripts/analise_pcap.py capturas/pcap_simulado_didatico.pcap
```

---

## Filtros Úteis no Wireshark

| Filtro de Exibição | Finalidade |
| :--- | :--- |
| `icmp` | Exibe todos os pacotes do protocolo ICMP (Camada 3). |
| `icmp.type == 8` | Exibe apenas solicitações `Echo Request`. |
| `icmp.type == 0` | Exibe apenas respostas `Echo Reply`. |
| `ip.src == 198.51.100.0/24` | Isola os pacotes com origem falsificada na faixa de documentação `RFC 5737`. |
| `icmp && ip.addr == <IP_ALVO>` | Exibe o tráfego ICMP trocado com a Máquina Alvo. |
