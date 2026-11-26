# Apresentação Interativa (`slides/`)

O arquivo **`apresentacao_camada3.html`** é uma apresentação web autocontida (HTML5, CSS3 e JavaScript puro, sem dependências externas ou necessidade de internet) desenvolvida para a defesa prática do trabalho.

---

## Como Abrir

Basta abrir o arquivo `slides/apresentacao_camada3.html` em qualquer navegador moderno (Chrome, Edge, Brave ou Firefox):

```bash
xdg-open slides/apresentacao_camada3.html
```

---

## Atalhos de Navegação

| Tecla / Botão | Função |
| :---: | :--- |
| `→` / `Espaço` / `PageDown` | Avança para o próximo slide |
| `←` / `PageUp` | Retorna ao slide anterior |
| `Home` / `End` | Vai para o primeiro / último slide |
| `F` | Alterna **Tela Cheia** (oculta barras superior e inferior para projeção limpa) |
| `T` | Alterna entre **Modo Escuro** (padrão) e **Modo Claro** |
| `G` | Abre o índice rápido para saltar diretamente para qualquer slide |

---

## Estrutura dos 9 Slides

1. **Capa & Modelo OSI:** Equipe, recorte do tema e destaque da Camada 3 (Rede).
2. **Por que a Camada 3 é Vulnerável por Design:** Causa raiz na `RFC 791`, *IP Spoofing* e *ICMP Flood*.
3. **O que é o ICMP (`RFC 792`):** Ciclo `Echo Request (Type 8)` / `Echo Reply (Type 0)` e ausência de *handshake*.
4. **Anatomia do IP Spoofing:** Inspetor interativo do cabeçalho IPv4 (Pacote Real vs. Spoofado) e diagrama de *Blind Spoofing*.
5. **Anatomia do ICMP Flood:** Comparativo visual de taxa (`pps`) e saturação de fila/CPU no Kernel do alvo.
6. **Simulador Interativo de Pacotes (L2 + L3):** Simulação ao vivo de *Ping Normal*, *IP Spoofing* e *Flood com Rotação*, contrastando o MAC fixo na Camada 2 com os IPs falsificados na Camada 3.
7. **Raio-X do Algoritmo Scapy:** Fluxograma cíclico 2×2 sincronizado passo a passo com a anatomia do pacote injetado via `conf.L3socket`.
8. **Mitigação na Prática:** Diagramas em grade lado a lado para **Rate Limiting no Kernel (`nftables`)** contra ICMP Flood e **Validação de Rota Reversa (`uRPF` / `BCP 38`)** contra IP Spoofing.
9. **Síntese & Referências Normativas:** Fechamento técnico e RFCs da IETF.
