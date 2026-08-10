from ttls.record import TTLSRecord, RecordType
from ttls.handshake import ClientHello, CipherSuite

class TTLSSession:
    def __init__(self, transport):
        """
            send(data: bytes)
            recv() -> bytes
        """
        self.transport = transport

    def send_record(self, record: TTLSRecord):
        self.transport.send(record.pack())

    def recv_record(self) -> TTLSRecord:
        data = self.transport.recv()

        return TTLSRecord.unpack(data)

    def send_client_hello(self):
        hello = ClientHello(
            CipherSuite.TTLS_KYBER
        )

        record = TTLSRecord(
            RecordType.HANDSHAKE,
            hello.pack()
        )

        self.send_record(record)