from ttp.connection import TTPConnection

def ttp_client(message: str) -> None:
    connection = TTPConnection(
    local_ip="127.0.0.1",
    remote_ip="127.0.0.1",
    local_port=50000,
    remote_port=8443,
)

    connection.connect()

    connection.send(message.encode("utf-8"))

    connection.close()

from ttp.connection import TTPConnection

def ttp_server(host: str, port: int) -> None:
    listener = TTPConnection(
        local_ip=host,
        local_port=port,
    )

    connection = listener.accept()

    dados = connection.recv()

    print(dados.decode("utf-8"))

    connection.close()