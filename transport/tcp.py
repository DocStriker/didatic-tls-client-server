import socket

def tcp_client(host: str, port: int, message: str) -> None:
    with socket.create_connection((host, port), timeout=10) as client_socket:
        print(f"[cliente] conectado em {host}:{port}")

        client_socket.sendall((message).encode("utf-8"))

        response = client_socket.recv(4096)

        print(f"[cliente] resposta: {response.decode('utf-8').strip()}")

def handle_client(conn: socket.socket, address: tuple[str, int]) -> None:
    print(f"[servidor] cliente conectado: {address[0]}:{address[1]}")

    data = conn.recv(4096)

    message = data.decode("utf-8").strip()

    print(f"[servidor] mensagem recebida: {message}")

    response = ("Olá do servidor TCP! Sua mensagem chegou sem criptografia.")
    
    conn.sendall(response.encode("utf-8"))

def tcp_server(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((host, port))
        server.listen()

        print(f"[servidor] aguardando conexões em {host}:{port}")

        while True:
            conn, addr = server.accept()
            handle_client(conn, addr)
            conn.close()