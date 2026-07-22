import socket

def udp_client(host: str, port: int, message: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.sendto(message.encode("utf-8"), (host, port))

        data, addr = client.recvfrom(4096)

        print(f"[cliente] resposta: {data.decode('utf-8').strip()} from {addr}")

def udp_server(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((host, port))

        print(f"[servidor] aguardando mensagens UDP em {host}:{port}")

        while True:
            data, addr = server.recvfrom(4096)

            message = data.decode("utf-8").strip()

            print(f"[servidor] mensagem recebida de {addr}: {message}")

            response = ("Olá do servidor UDP! Sua mensagem chegou sem criptografia.")

            server.sendto(response.encode("utf-8"), addr)