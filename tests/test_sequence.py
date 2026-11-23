from ttp.sequence import ReceiveStatus, SequenceSpace, seq_add, seq_diff, seq_leq, seq_lt

MAX = 0xFFFFFFFF


def test_comparacao_com_wraparound():
    assert seq_lt(MAX - 5, 10)          # 4294967290 vem ANTES de 10 (deu a volta)
    assert not seq_lt(10, MAX - 5)
    assert seq_leq(7, 7) and not seq_lt(7, 7)
    assert seq_add(MAX, 1) == 0
    assert seq_diff(3, MAX - 1) == 5    # distância "para frente"


def test_acknowledge_ignora_ack_velho_e_ack_do_futuro():
    seq = SequenceSpace(initial_sequence=MAX - 2)
    seq.advance_send(10)                              # SND.NXT deu a volta
    assert seq.bytes_in_flight == 10
    assert seq.acknowledge(seq_add(MAX - 2, 4))       # ack válido atravessando o zero
    assert seq.bytes_in_flight == 6
    assert not seq.acknowledge(seq_add(MAX - 2, 2))   # ack velho
    assert not seq.acknowledge(seq_add(MAX - 2, 50))  # ack de algo que nunca enviamos
    assert seq.bytes_in_flight == 6


def test_classify():
    seq = SequenceSpace()
    seq.recv_next = 1000
    assert seq.classify(1000, 100, 4096) is ReceiveStatus.EXPECTED
    assert seq.classify(900, 100, 4096) is ReceiveStatus.DUPLICATE   # [900,1000) já recebido
    assert seq.classify(950, 100, 4096) is ReceiveStatus.OVERLAP     # metade velha, metade nova
    assert seq.classify(1200, 100, 4096) is ReceiveStatus.FUTURE
    assert seq.classify(1000 + 4096, 10, 4096) is ReceiveStatus.OUT_OF_WINDOW


def test_classify_wraparound():
    seq = SequenceSpace()
    seq.recv_next = MAX - 10
    assert seq.classify(5, 10, 4096) is ReceiveStatus.FUTURE        # 16 bytes à frente, atravessando o 0
    assert seq.classify(MAX - 20, 5, 4096) is ReceiveStatus.DUPLICATE
