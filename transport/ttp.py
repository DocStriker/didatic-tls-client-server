from ttp.connection import TTPConnection
from ttls.session import TTLSSession
from ttls.record import TTLSRecord, RecordType

def client(host: str, port: int, message: str) -> None:
    connection = TTPConnection(
    local_ip=host,
    remote_ip=host,
    local_port=50000,
    remote_port=port,
    window_size=4096,
    side_name="Client"
)

    connection.connect()

    trp = TTLSSession(connection)
    print(f"[Client][TTP] Conectado em {host}:{port}")

    trp.send_record(TTLSRecord(RecordType.APPLICATION_DATA,b"Hello Server"))
    #connection.send(message.encode("utf-8"))
    print(f"[Client][TTP] Mensagem enviada.")

    # aguarda acknowledgements antes de fechar
    connection.wait_for_acks(timeout=3.0)

    connection.close()

def server(host: str, port: int) -> None:
    listener = TTPConnection(
        local_ip=host,
        local_port=port,
        window_size=4096,
        side_name="Server"
    )

    print(f"[Server][TTP] Aguardando conexões em {host}:{port}")

    connection = listener.accept()

    trp = TTLSSession(connection)

    print(f"[Server][TTP] Cliente conectado.")
    
    record = trp.recv_record()
    
    print(record.payload.decode())

    #dados = connection.recv()

    #print(f"[Server][TTP] Mensagem recebida: {dados.decode('utf-8')}")

    connection.close()