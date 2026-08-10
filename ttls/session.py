from ttls.record import TTLSRecord, RecordType
from ttls.handshake import ClientHello, ServerHello, Finished, CipherSuite
from enum import Enum

class TTLSState(Enum):

    NEW = 0

    CLIENT_HELLO_SENT = 1
    SERVER_HELLO_RECEIVED = 2

    SERVER_WAIT_CLIENT_HELLO = 3
    SERVER_HELLO_SENT = 4
    SERVER_WAIT_FINISHED = 5

    ESTABLISHED = 6

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

    def recv_client_hello(self) -> ClientHello:

        record = self.recv_record()

        if record.record_type != RecordType.HANDSHAKE:
            raise ValueError(
                "Esperado um registro HANDSHAKE."
            )

        return ClientHello.unpack(record.payload)

    def send_server_hello(self, cipher_suite):

        hello = ServerHello(cipher_suite)

        record = TTLSRecord(
            RecordType.HANDSHAKE,
            hello.pack(),
        )

        self.send_record(record)

    def recv_server_hello(self) -> ServerHello:
        record = self.recv_record()

        if record.record_type != RecordType.HANDSHAKE:
            raise ValueError(
                "Esperado um registro HANDSHAKE."
            )

        return ServerHello.unpack(record.payload)

    def send_finished(self):

        finished = Finished()

        record = TTLSRecord(
            RecordType.HANDSHAKE,
            finished.pack()
        )

        self.send_record(record)

    def recv_finished(self) -> Finished:

        record = self.recv_record()

        if record.record_type != RecordType.HANDSHAKE:
            raise ValueError(
                "Esperado um registro HANDSHAKE."
            )

        return Finished.unpack(
            record.payload
        )