# TLS na prática: Cliente e Servidor + TTP v2

Projeto didático em Python para ver, na prática, como funcionam os protocolos de
transporte que sustentam a internet. Ele contém três frentes:

1. **TLS na prática** (`server.py` / `client.py`): um cliente e servidor TLS
   reais, usando o módulo `ssl` do Python, para observar um canal
   criptografado de ponta a ponta.
2. **TCP / UDP / TTP** (`main.py` + `applications/` + `transport/`): a mesma
   aplicação cliente/servidor rodando sobre três transportes diferentes —
   o TCP e o UDP reais do sistema operacional, e o **TTP (Tarek Transport
   Protocol)**, um protocolo de transporte confiável construído do zero em
   cima de *raw sockets* IPv4, para estudar por dentro como um protocolo
   como o TCP resolve os problemas de confiabilidade, ordenação e controle
   de fluxo.
3. **Sniffer didático** (`wireshark/`): um "mini Wireshark" em Python (via
   Scapy) que decodifica ao vivo os pacotes TCP, UDP e TTP trocados pela
   aplicação, mostrando cabeçalhos, flags e payload.

## 📄 Documentação técnica completa: TTP v2

A documentação técnica completa do protocolo TTP — arquitetura, formato do
cabeçalho, máquina de estados, handshake de 3 vias, janela deslizante,
retransmissão, checksum, e o passo a passo de como rodar o projeto nos três
modos (TCP/UDP/TTP) — está no arquivo **`TTP_v2_Documentacao_Tecnica.pdf`**
em docs/.

### Resumo rápido do TTP v2

O **TTP (Tarek Transport Protocol)** é um protocolo de transporte confiável
e orientado a conexão, implementado inteiramente em Python sobre *raw
sockets* (sem usar `SOCK_STREAM`/`SOCK_DGRAM` do sistema operacional). Ele
reproduz, de forma simplificada e didática, os principais mecanismos do TCP:

| Mecanismo | O que faz | Onde está implementado |
|---|---|---|
| Handshake de 3 vias | Estabelece a conexão (SYN → SYN-ACK → ACK) | `ttp/connection.py` |
| Números de sequência / ACK | Garante ordenação e confirmação de entrega | `ttp/sequence.py` |
| Janela deslizante (*sliding window*) | Controla quantos bytes podem estar "em trânsito" sem confirmação | `ttp/window.py` |
| Retransmissão por timeout | Reenvia pacotes perdidos automaticamente | `ttp/timer.py`, `ttp/retransmission.py` |
| Checksum (pseudo-header) | Detecta corrupção e pacotes endereçados incorretamente | `ttp/checksums.py` |
| Encapsulamento IPv4 manual | Monta/lê o cabeçalho IP à mão, já que não existe suporte de kernel para o TTP | `ttp/ipv4.py`, `ttp/socket.py` |
| Encerramento gracioso | Handshake de fechamento (FIN / FIN-ACK) | `ttp/connection.py` |

Como o TTP usa *raw sockets*, ele **exige privilégios administrativos**
(root no Linux, Administrador/WSL no Windows) para funcionar. Todos os
detalhes de execução — inclusive como capturar o tráfego ao vivo com o
sniffer — estão na documentação em PDF.

Antes de usar o sniffer, é preciso instalar a biblioteca libcap do linux
para a captura de pacotes seguindo os comandos:

```bash
sudo apt update

sudo apt install libpcap-dev tcpdump

sudo .venv/bin/python wireshark/sniffer.py
```

### Como executar o TTP (resumo)

```bash
# Criar uma venv
python -m venv .venv

# Iniciar a venv
source .venv/bin/activate

# Instalar as bibliotecas necessárias
pip install -r requirements.txt

# Terminal 1 (privilégio de administrador/root)
sudo python main.py --mode server --protocol TTP --port 8443

# Terminal 2 (privilégio de administrador/root)
sudo python main.py --mode client --protocol TTP --port 8443 --message "Olá via TTP!"
```

Os mesmos comandos funcionam trocando `--protocol TTP` por `--protocol TCP`
ou `--protocol UDP` (nesses dois casos não é necessário privilégio elevado).

---

# TLS na prática: Cliente e Servidor

Projeto simples em Python para ver TLS funcionando de ponta a ponta.

O servidor escuta em `127.0.0.1:8443`, apresenta um certificado local e recebe uma mensagem. O cliente valida esse certificado, abre uma conexao TLS, envia uma mensagem e mostra a resposta.

## Estrutura

```text
tls-na-pratica/
  client.py
  server.py
  generate_certs.py
  run_generate_certs.ps1
  run_client.ps1
  run_server.ps1
  certs/
    .gitkeep
```

## Como executar

Primeiro, gere o certificado local de desenvolvimento:

```bash
pip install cryptography
python generate_certs.py
```

Depois, abra dois terminais na pasta do projeto.

No terminal 1, suba o servidor:

```bash
python server.py
```

No terminal 2, rode o cliente:

```bash
python client.py
```

No Windows, se `python` nao estiver no PATH, voce tambem pode usar os atalhos para rodar cliente e servidor:

```powershell
.\run_generate_certs.ps1
.\run_server.ps1
.\run_client.ps1
```

Saida esperada no cliente:

```text
[cliente] conectado em 127.0.0.1:8443
[cliente] TLS usado: TLSv1.3 | cifra: ...
[cliente] resposta do servidor: Ola do servidor TLS! Sua mensagem chegou por um canal criptografado.
```

## O que observar

- `server.py` usa `ssl.PROTOCOL_TLS_SERVER`, carrega `certs/server.crt` e `certs/server.key`, e envolve o socket TCP com TLS.
- `client.py` usa `ssl.create_default_context`, confia explicitamente no certificado `certs/server.crt` e valida o hostname/IP.
- Se voce trocar o certificado, apagar a CA do cliente ou usar um host que nao esteja no certificado, a conexao deve falhar. Essa falha e boa: significa que a verificacao TLS esta ativa.

## Regenerar o certificado

O certificado local nao fica no repositorio, porque a chave privada nao deve ser publicada. Para gerar ou regenerar:

```bash
pip install cryptography
python generate_certs.py
```

Esse certificado e autoassinado e serve apenas para teste local. Em producao, use certificados emitidos por uma autoridade certificadora confiavel, como Let's Encrypt, ou pela infraestrutura da sua organizacao.

## Testes rapidos

Enviar outra mensagem:

```bash
python client.py --message "Teste TLS na pratica"
```

Usar outra porta:

```bash
python server.py --port 9443
python client.py --port 9443
```
