import hashlib

from ttp.connection import TTPConnection
from ttls.session import TTLSSession, TTLSState
from ttls.record import TTLSRecord, RecordType
from ttls.handshake import select_cipher_suite
from ttls.cipher import TTLSCipher
from ttp.server import TTPServer

def client(host: str, port: int, message: str) -> None:
    connection = TTPConnection(
    local_ip=host,
    remote_ip=host,
    local_port=50000,
    remote_port=port,
    window_size=4096,
    side_name="Client"
)
    
    # Inicia a conexão TTP com o servidor
    connection.connect()

    # Inicia a sessão TTLS sobre a conexão TTP
    ttls = TTLSSession(connection)

    print(f"[Client][TTP] Conectado em {host}:{port}")

    # 1. TTLS ClientHello
    ttls.send_client_hello()

    ttls.state = TTLSState.CLIENT_HELLO_SENT

    # 2. Aguarda ServerHello
    server_hello = ttls.recv_server_hello()

    ttls.state = TTLSState.SERVER_HELLO_RECEIVED

    print(
        f"[Client][TTLS] Cipher suite selecionada: "
        f"{server_hello.cipher_suite.name}"
    )

    ttls.send_finished()

    # O ServerHello e o Finished do servidor fazem parte do handshake TTLS.
    # Sem aguardar esse Finished, o cliente pode enviar FIN enquanto o
    # servidor ainda está concluindo o handshake.
    ttls.recv_finished()

    ttls.state = TTLSState.ESTABLISHED

    print("[Client][TTLS] Handshake concluído.")

    # 3. Só depois do handshake podemos enviar dados
    # ttls.send_record(TTLSRecord(RecordType.APPLICATION_DATA, message.encode("utf-8")))

    shared_secret = hashlib.sha256(b"TTLS TEST SECRET").digest()

    ttls.cipher = TTLSCipher.from_shared_secret(shared_secret)

    ttls.send_application_data(message.encode("utf-8"))

    print("[Client][TTLS] Mensagem enviada.")

    # Aguarda brevemente por ACKs antes de fechar; reduzir para 0.5s
    # diminui latência de fechamento em ambientes de teste.
    acked = connection.wait_for_acks()

    if not acked:
        print("[Client][TTP] Timeout aguardando ACKs.")

    #print("[Client] Iniciando close()")

    connection.close()

    #print("[Client] Conexão encerrada")

def server(host: str, port: int) -> None:
    listener = TTPServer(
        local_ip=host,
        local_port=port,
        window_size=4096,
        side_name="Server"
    )

    listener.start()

    print(f"[Server][TTP] Aguardando conexões em {host}:{port}") 

    connection = listener.accept()

    ttls = TTLSSession(connection)

    client_hello = ttls.recv_client_hello()
    
    cipher_suite = select_cipher_suite(client_hello.cipher_suite)

    ttls.send_server_hello(cipher_suite)

    ttls.recv_finished()

    ttls.send_finished()

    print("[Server][TTLS] Handshake concluído.")

    ttls.state = TTLSState.ESTABLISHED

    # record = ttls.recv_record()

    shared_secret = hashlib.sha256(b"TTLS TEST SECRET").digest()
    
    ttls.cipher = TTLSCipher.from_shared_secret(shared_secret)

    plaintext = ttls.recv_application_data()

    print(
        f"[Server][TTLS] Mensagem recebida: "
        f"{plaintext.decode('utf-8')}"
    )

    # if record.record_type != RecordType.APPLICATION_DATA:
    #    raise ValueError("Esperado APPLICATION_DATA.")

    # print(
    #     f"[Server][TTLS] Mensagem recebida: "
    #     f"{record.payload.decode('utf-8')}"
    # )

    #print("[Server] Iniciando close()")

    connection.close()

    listener.close()

    #print("[Server] Conexão encerrada")