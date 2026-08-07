from ttls.record import TTLSRecord

class TTLSSession:
    def __init__(self, transport):
        """
        transport deve implementar:

            send(data: bytes)
            recv() -> bytes
        """
        self.transport = transport

    def send_record(self, record: TTLSRecord):
        self.transport.send(record.pack())

    def recv_record(self) -> TTLSRecord:
        data = self.transport.recv()

        return TTLSRecord.unpack(data)