from ttp.connection import TTPConnection

def client(host: str, port: int, message: str) -> None:
    connection = TTPConnection(
    local_ip=host,
    remote_ip=host,
    local_port=50000,
    remote_port=port,
    window_size=4096
)

    connection.connect()
    connection.send(message.encode("utf-8"))

    # aguarda acknowledgements antes de fechar
    connection.wait_for_acks(timeout=3.0)

    connection.close()

def server(host: str, port: int) -> None:
    listener = TTPConnection(
        local_ip=host,
        local_port=port,
        window_size=4096
    )

    connection = listener.accept()

    dados = connection.recv()

    print(dados.decode("utf-8"))

    connection.close()