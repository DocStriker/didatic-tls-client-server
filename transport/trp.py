from trp.trp import TRPSocket, TRPRecord, RecordType

def client (message: str) -> None:
    with TRPSocket() as client:
                client.send_record(TRPRecord(RecordType.APPLICATION_DATA, message.encode("utf-8")))

                response = client.recv_record()
                print(f"[Client][TRP] Resposta: {response.payload.decode('utf-8').strip()}")