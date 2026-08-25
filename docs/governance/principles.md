# TTP Governance Principles

## GOV-001 - Security by Design

### Principle

A segurança deve ser considerada durante o projeto e evolução do TTP/TTLS, e não adicionada posteriormente como uma camada corretiva.

### Rationale

Isso significa que uma nova funcionalidade deve considerar segurança desde o início.

Por exemplo, se adicionarmos:

TTP
 └── File Transfer

Não deveríamos implementar primeiro e perguntar depois, a análise deveria acontecer antes.

### Application

Para cada nova funcionalidade:

Feature --> Security Analysis --> Architecture --> Implementation

## GOV-002 - Defense in Depth

### Principle

A segurança do sistema não deve depender de um único mecanismo de proteção.

### Rationale

Por exemplo, no TTLS:

Application Data --> TTLS --> AEAD --> TTP --> Network

Se uma camada apresentar um problema, outras propriedades ainda podem limitar o impacto.

### Application

No TTP podemos ter:

Packet validation + Sequence validation + State validation + Checksum + TTLS authentication

## GOV-003 - Traceability

### Principle

Toda decisão relevante de arquitetura, segurança ou protocolo deve possuir rastreabilidade até seu requisito, risco ou justificativa técnica.

### Rationale

Por exemplo:

Requirement --> REQ-012 --> Risk --> RISK-004 --> ADR-007 --> Implementation --> TEST-021 --> Evidence

Isso significa que podemos perguntar:

"Por que existe esse campo no header?"

E encontrar a resposta.

Ou:

"Qual requisito justificou esse comportamento do handshake?"

Também conseguimos rastrear.

Esse princípio será especialmente importante quando o TTP crescer.

### Application

-

## GOV-004 - Change Management

### Principle

Mudanças que possam alterar comportamento, segurança, compatibilidade ou interoperabilidade do protocolo devem ser avaliadas e documentadas antes de serem incorporadas.

### Rationale

Por exemplo:

Mudança trivial
Renomear variável interna

Provavelmente:

Review simples
Mudança importante
Alterar TTP header

Precisamos analisar:

Wire compatibility
Parser
Receiver
Sniffer
Tests
Documentation
Security
Mudança crítica
Alterar handshake TTLS

Pode exigir:

ADR
Threat analysis
Tests
Interop validation
Packet capture

### Application

Portanto:

Impacto da mudança --> Nível de governança necessário

## GOV-005 - Evidence Based

### Principle

Afirmações sobre segurança, confiabilidade ou comportamento do protocolo devem ser sustentadas por evidências verificáveis.

### Rationale

Não queremos:

"O handshake é seguro."

Queremos:

Claim --> Security property --> Test --> Result --> Evidence

Por exemplo:

Afirmação

O TTLS detecta alteração do ciphertext.

### Application

Evidência
Original ciphertext --> Modify byte --> Decrypt --> Authentication failure

## GOV-006 - Least Privilege

### Principle

Cada componente deve possuir apenas os privilégios necessários para executar sua função.

### Rationale

Por exemplo, se futuramente tivermos:

TTLS Session --> Key Manager

A sessão não deveria necessariamente possuir acesso irrestrito a todo material criptográfico.

Da mesma maneira:

Application --> TTP

A aplicação deveria interagir através da interface definida, em vez de manipular diretamente estado interno do protocolo.

### Application

## GOV-007 - Risk Proportionality

### Principle

O nível de controle aplicado deve ser proporcional ao risco associado à mudança ou componente.

### Rationale

Imagine três alterações:

A → corrigir typo na documentação
B → alterar timeout
C → alterar algoritmo criptográfico

Não faz sentido exigir a mesma quantidade de análise para todas.

### Application

Podemos ter:

Risco baixo --> Review simples
Risco médio --> Review + testes
Risco alto --> Threat analysis

+ ADR
+ testes
+ evidências
+ revisão de segurança