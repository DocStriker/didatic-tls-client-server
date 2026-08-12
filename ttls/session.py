from ttls.record import TTLSRecord, RecordType
from ttls.handshake import ClientHello, ServerHello, Finished, CipherSuite, HandshakeMessage, HandshakeType
from ttls.transcript import HandshakeTranscript
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
        self.transcript = HandshakeTranscript()

    def send_record(self, record: TTLSRecord):
        self.transport.send(record.pack())

    def recv_record(self) -> TTLSRecord:
        data = self.transport.recv()

        return TTLSRecord.unpack(data)

    def send_client_hello(self):
        hello = ClientHello(CipherSuite.TTLS_AES_256_GCM)

        message = HandshakeMessage(HandshakeType.CLIENT_HELLO, hello.pack())

        self.transcript.add(message.pack())

        record = TTLSRecord(RecordType.HANDSHAKE, message.pack())

        self.send_record(record)

    def send_server_hello(self, cipher_suite):
        hello = ServerHello(cipher_suite)
    
        message = HandshakeMessage(HandshakeType.SERVER_HELLO, hello.pack())
    
        self.transcript.add(message.pack())
    
        record = TTLSRecord(RecordType.HANDSHAKE, message.pack())
    
        self.send_record(record)

    def send_finished(self):
        verify_data = self.transcript.digest()

        finished = Finished(verify_data)
    
        message = HandshakeMessage(HandshakeType.FINISHED, finished.pack())
        
        record = TTLSRecord(RecordType.HANDSHAKE, message.pack(),)
    
        self.send_record(record)

    def recv_client_hello(self) -> ClientHello:
        message = self.recv_handshake_message()

        self.transcript.add(message.pack())

        if message.message_type != HandshakeType.CLIENT_HELLO:
            raise ValueError("Esperado CLIENT_HELLO.")

        return ClientHello.unpack(message.payload)

    def recv_server_hello(self) -> ServerHello:
        message = self.recv_handshake_message()

        self.transcript.add(message.pack())

        if message.message_type != HandshakeType.SERVER_HELLO:
            raise ValueError("Esperado SERVER_HELLO.")

        return ServerHello.unpack(message.payload)

    def recv_finished(self) -> Finished:
        message = self.recv_handshake_message()

        if message.message_type != HandshakeType.FINISHED:
            raise ValueError("Esperado FINISHED.")

        finished = Finished.unpack(message.payload)

        expected = self.transcript.digest()

        if finished.verify_data != expected:
            raise ValueError("Finished inválido: transcript não confere.")

        return finished

    def recv_handshake_message(self) -> HandshakeMessage:
        record = self.recv_record()

        if record.record_type != RecordType.HANDSHAKE:
            raise ValueError("Esperado um registro HANDSHAKE.")

        message = HandshakeMessage.unpack(record.payload)

        return message