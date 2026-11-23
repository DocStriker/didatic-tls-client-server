# Análise e melhorias — TTP v2 + TTLS v2

Este documento explica **o que estava errado**, **como cada problema foi
reproduzido** e **como a sincronia entre cliente e servidor funciona agora**.
Onde há fórmula, ela vem com números de exemplo para você substituir e conferir.

> O PDF `docs/TTP_v2_Documentacao_Tecnica.pdf` descreve o projeto **antes** destas
> mudanças (janela fixa de 4096, timeout fixo de 1 s, etc.) e não foi alterado.

---

## 1. Problemas reproduzidos no código original

Os itens 1–5 foram **executados** com raw sockets reais no loopback antes de qualquer
alteração e re-executados depois com o mesmo script. O item 6 e as demais causas abaixo
vêm da leitura do código; todas passaram a ter teste automatizado (seção 4).

| # | Cenário | Antes | Depois |
|---|---|---|---|
| 1 | Enviar 10 KB (janela de 4096) | **trava para sempre**: o pacote (> janela) nunca sai da fila (`queue=1, pending=0`) | recebe 10000/10000 |
| 2 | Enviar 70 KB | idem; e `MAX_PACKET_SIZE=65535` estoura o campo `total_length` do IP | recebe 70000/70000 |
| 3 | Perder 1 pacote de dados | **nunca retransmite** (`pending=1` eternamente) | 1 retransmissão, recebe tudo |
| 4 | 1 pacote com checksum ruim | `ValueError` **mata a thread receptora**; conexão fica surda | descartado; 1 retransmissão |
| 5 | 2 conexões no mesmo processo | `AttributeError: 'NoneType' has no attribute 'info'` (logger) | ok |
| 6 | `recv()` quando o par fecha | espera ocupada **para sempre** | devolve `b""` (EOF) |

### Causas-raiz, por arquivo

**`ttp/connection.py` (sincronia)**
- **Timer só checado ao chegar pacote.** `_wait_for_packet()` fazia `continue` no timeout do socket e só retornava com um pacote; a checagem de retransmissão ficava *depois* dele. Se o único pacote em voo se perdia, nada mais chegava → deadlock.
- **Timer parado por qualquer ACK.** `_process_ack` chamava `retransmission.stop()` até em ACK duplicado e `_flush_window` só o religava se `len(pending)==1`. Com 3 pacotes e 1 perdido, o timer morria e a perda ficava sem cobertura.
- **Corrida de dados.** A thread receptora (`_process_ack → _flush_window`) e `send()` mexiam em `queue/pending` sem o mesmo lock.
- **Sem controle de fluxo.** A janela era o buffer *local* (4096), ignorando a janela que o par anuncia.
- **`send()` construía todos os pacotes antes de enviar** (avançando `send_next` de uma vez) e cada um nascia com ACK/janela já desatualizados.
- **Dados sem flag ACK.** Se o ACK final do handshake se perdia, o servidor ficava em `SYN_RECEIVED` filtrando `ACK` e **ignorava os dados** do cliente.
- **Sem retransmissão de SYN/SYN-ACK**, e `connect()` sem timeout: servidor fora do ar = cliente travado para sempre.
- **FIN.** `FIN|ACK` consumia número de sequência e era tratado como ACK puro; FIN fora de ordem derrubava a conexão perdendo dados; `close()` podia enviar FIN antes dos dados da fila saírem; só existia um estado `FIN_WAIT` (sem meio-fechamento nem EOF).
- **Números de sequência de 32 bits sem wraparound** (ISN aleatório até `0xFFFFFFFF` + `struct.pack('!I')`) e comparados com `<`/`>`.
- **Servidor de uma conexão.** `TTPServer` compartilhava um socket entre conexões; cada thread receptora *descartava* pacotes que não eram dela.

**`ttls/` (segurança e enquadramento)**
- Segredo compartilhado **fixo no código** (`sha256(b"TTLS TEST SECRET")`) → qualquer um deriva a chave; toda sessão usa a mesma.
- `Finished` = `sha256(transcript)` **sem chave** → qualquer atacante calcula; e os dois `Finished` eram idênticos (reflexão).
- Nonce AES-GCM aleatório por registro e **sem número de sequência**: replay, reordenação e remoção de registros eram indetectáveis; mesma chave nos dois sentidos.
- Sessão assumia **1 segmento TTP = 1 registro** (`recv_record` chamava `transport.recv()` uma vez). Registro > MSS ou dois coalescidos quebravam. A docstring citava um `recv_record()` “streaming-safe” que não existia.
- `length` de 4 bytes sem limite (anunciar 4 GB = esgotar memória). `ttls.state` nunca verificado. Sem alertas / `close_notify`. `alert.py` vazio. Suite `KYBER` “aceita” mas não implementada.

**Outros**: `log_config.py` (indentação, ver #5), `unpack` confiava em `header_length` vindo da rede, cliente com porta fixa 50000 (dois clientes colidem), UDP sem timeout, sniffer escondia retransmissões (`seen` global) e quebrava com registro fatiado, `README` descrevia arquivos que não existem.

---

## 2. Como a sincronia funciona agora

Três camadas independentes, cada uma pegando uma classe de falha:

```
App    número de sequência da mensagem   -> perda/duplicação/ordem no nível da aplicação
TTLS   nonce = IV XOR nº do registro     -> replay, reordenação, remoção, adulteração
TTP    SEQ/ACK, janela, RTO, fast retx   -> perda, duplicação, reordenação, corrupção de pacotes
```

### 2.1 Aritmética de sequência (módulo 2³²)

`a` vem antes de `b` ⇔ `(a − b) mod 2³² ≥ 2³¹`.

Substituindo: `a = 4 294 967 290`, `b = 5`
`(a − b) mod 2³² = 4 294 967 285 ≥ 2 147 483 648` → **a vem antes de b**. ✔ (com `<` comum daria o contrário.)

### 2.2 Controle de fluxo (janela do par)

```
usable = janela_do_par − bytes_em_voo
n      = min(MSS, bytes_no_buffer, usable)
```
Exemplo: janela do par = 4096, MSS = 1400, em voo = 2800 → `usable = 4096 − 2800 = 1296`. Como `1296 < 1400` e há dado em voo, **espera o ACK** (evita segmentos minúsculos = “janela boba”). Com em voo = 0: `usable = 4096`, `n = min(1400, …, 4096) = 1400` ✔.

O receptor anuncia `janela = capacidade − bytes_não_lidos`. Capacidade 4096 com 3000 bytes ainda não lidos → livre = 1096 `< min(MSS, 4096/2) = 1400` → anuncia **0**. O remetente pára; quando a aplicação lê e o livre volta a ≥ 1400, o receptor manda um ACK de “janela reaberta”. Se esse ACK se perder, o **persist timer** do remetente sonda o par (testado em `test_janela_zero_perdida_e_recuperada_por_sonda`).

### 2.3 RTO adaptativo (RFC 6298)

```
1ª medição R:   SRTT = R              RTTVAR = R/2
seguintes:      RTTVAR = 0,75·RTTVAR + 0,25·|SRTT − R|
                SRTT   = 0,875·SRTT  + 0,125·R
sempre:         RTO    = SRTT + max(G, 4·RTTVAR)     (e dobra a cada timeout)
```
R₁ = 100 ms → SRTT = 100, RTTVAR = 50, **RTO = 100 + 4·50 = 300 ms**.
R₂ = 140 ms → RTTVAR = 0,75·50 + 0,25·|100−140| = **47,5**; SRTT = 0,875·100 + 0,125·140 = **105**; **RTO = 105 + 4·47,5 = 295 ms**.
Timeout: 295 → 590 → 1180 ms … até `rto_max`. (Antes era 1000 ms fixo: 3000× o RTT de um loopback.)
Algoritmo de Karn: RTT de segmento retransmitido **não** entra na média.

### 2.4 Fast retransmit (linha do tempo)

Remetente envia 6 segmentos de 1400 bytes (SEQ relativo 0, 1400, 2800, 4200, 5600, 7000) e o **3º (2800) se perde**:

| chega | receptor responde | remetente |
|---|---|---|
| seg 0 | ACK 1400 | ok |
| seg 1400 | ACK 2800 | ok |
| seg 4200 (buraco!) | ACK **2800** (dup 1) | guarda 4200 fora de ordem |
| seg 5600 | ACK **2800** (dup 2) | |
| seg 7000 | ACK **2800** (dup 3) | **retransmite SEQ 2800 já**, sem esperar RTO |
| seg 2800 | ACK **8400** (cobre tudo) | libera os guardados |

Se houver mais de um buraco, o **ACK parcial** (NewReno) dispara a retransmissão do próximo imediatamente.

### 2.5 Nonce do TTLS

`nonce_i = IV XOR i`. Com `IV = 0x…A5` (último byte) e `i = 3` → último byte `0xA5 ⊕ 0x03 = 0xA6`.
Emissor e receptor contam `i` sozinhos. Se um registro some, repete ou troca de lugar, o `i` do receptor deixa de bater, o nonce difere e **a tag GCM falha** → `BAD_RECORD_MAC`, sessão derrubada. (Testes: `test_replay_…`, `test_reordenacao_…`, `test_registro_removido_…`.)

### 2.6 Handshake TTLS v2

```
C → S  ClientHello  (random, suites, X25519 pública)
S → C  ServerHello  (random, suite, X25519 pública)
S → C  ServerAuth   (Ed25519 pública + assinatura de H(CH‖SH))
C → S  Finished     HMAC(finished_key_c, H(CH‖SH‖SA))
S → C  Finished     HMAC(finished_key_s, H(CH‖SH‖SA‖CF))
chaves = HKDF-SHA256(ECDHE, salt = H(CH‖SH))  → chave/IV por sentido + chaves de Finished
```
Sigilo futuro (ECDHE efêmero), autenticação do servidor (pinning da chave pública), `Finished` autenticado.
Sem `certs/ttls_identity.pub` o cliente avisa que o servidor **não está autenticado**.

---

## 3. Conexão contínua

- `TTPServer` aceita **vários clientes**; um `PacketDispatcher` entrega cada pacote à conexão certa (chave IP+porta do par).
- Estados completos (`FIN_WAIT_1/2`, `CLOSE_WAIT`, `LAST_ACK`, `CLOSING`, `TIME_WAIT`), **meio-fechamento** (`shutdown_write`) e EOF (`recv() == b""`).
- **RST** para pacote sem conexão; `TTPRefused` imediato; abort limpo.
- **Keepalive** (sonda = ACK com SEQ−1, que o par obrigatoriamente responde) → `TTPTimeout` em par morto, acordando quem estava em `recv()`/`send()`.
- Retransmissões esgotadas → `TTPTimeout` (e não pendura mais ninguém).
- Cliente com porta efêmera; IP local descoberto pelo kernel.
- TTLS: `ping()` (heartbeat com RTT), `close_notify`, detecção de truncamento (`TTLSTruncated`).

Demo:
```bash
sudo python main.py --mode server --protocol TTP --port 8443
sudo python main.py --mode client --protocol TTP --port 8443 --message "oi" --count 10 --interval 0.5 --keepalive 5
```

---

## 4. Testes (`pytest tests`, 54 testes)

`ttp/simnet.py` é uma rede simulada (sem root) com perda, duplicação, reordenação,
corrupção, atraso e partição de enlace, com semente fixa. Cobre: transferência
íntegra nos dois sentidos sob cada defeito e todos juntos, perda do único pacote em
voo, fast retransmit, mensagem > janela, leitor lento (janela zero), SYN/SYN-ACK/ACK
perdidos, wraparound de ISN, `close()` com dados na fila, meio-fechamento, ACK final
perdido, RST, keepalive, esgotamento de retransmissões, vários clientes; TTLS: bit
alterado, cabeçalho alterado, replay, reordenação, remoção, reflexão, MITM, servidor
anônimo, `length` gigante, versão antiga, truncamento; e um teste ponta a ponta com
raw sockets reais (pulado se não for root).

---

## 5. Limitações e próximos passos

- **Sem controle de congestionamento** (slow start / AIMD): só controle de fluxo. É o próximo passo natural.
- Sem SACK, sem negociação de MSS/Path-MTU, sem ACK atrasado.
- `TTLS_KYBER_AES_256_GCM` continua **reservada** (recusada na negociação); para um híbrido pós-quântico real use ML-KEM (FIPS 203).
- Pinning de chave Ed25519 no lugar de certificados X.509/CA.
- Sem renegociação/rekey (limite 2⁴⁰ registros por chave, depois erro).
- Mensagens de aplicação limitadas a 16 KB − 4 (1 registro = 1 mensagem).
- TTP continua exigindo root (raw sockets) e usa o protocolo IP 253 (reservado para experimentos).
