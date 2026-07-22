from trp.trp import TRPSocket, TRPRecord, RecordType

def trp_client (message: str) -> None:
    with TRPSocket() as client:
                client.send_record(
                    TRPRecord(RecordType.APPLICATION_DATA, message.encode("utf-8"))
                )

                response = client.recv_record()
                print(f"[cliente] resposta: {response.payload.decode('utf-8').strip()}")