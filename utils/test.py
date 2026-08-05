print("\U0001F512")
#print(payload.decode("utf-8", errors="ignore"))

def _wait_for_ack(self, packet: TTPPacket) -> None:

    expected_ack = (packet.sequence_number + packet.sequence_space)

    self.retransmission.start()

    while True:
        old_timeout = self.socket.receive_socket.gettimeout()

        self.socket.receive_socket.settimeout(0.1)

        try:
            ack, _ = self._wait_for_packet(TTPFlags.ACK)

            if ack.acknowledgment_number != expected_ack:
                continue

            self.sequence.acknowledge(ack.acknowledgment_number)

            self.window.acknowledge(ack.acknowledgment_number)

            self.retransmission.stop()

            print("[TTP] ACK confirmado.")

            return

        except socket.timeout:
            if not self.retransmission.expired:
                continue

            if self.retransmission.exhausted:
                raise TimeoutError("Falha na transmissão.")

            print("[TTP] Timeout. Retransmitindo...")

            for packet in self.window.packets_for_retransmission():
                self._transmit_packet(packet)

            self.retransmission.restart()
        finally:
            self.socket.receive_socket.settimeout(old_timeout)