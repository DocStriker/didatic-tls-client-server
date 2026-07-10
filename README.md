# TLS na pratica: Cliente e Servidor

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
