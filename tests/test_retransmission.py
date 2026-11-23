import pytest

from ttp.retransmission import RetransmissionManager


def test_rto_segue_a_rfc_6298():
    rtx = RetransmissionManager(min_rto=0.0, max_rto=60)

    # 1ª amostra R=100ms: SRTT=100, RTTVAR=50, RTO=100+4*50=300ms
    assert rtx.sample(0.100) == pytest.approx(0.300)

    # 2ª amostra R=140ms: RTTVAR=0.75*50+0.25*|100-140|=47.5 ; SRTT=0.875*100+0.125*140=105
    # RTO = 105 + 4*47.5 = 295ms
    assert rtx.sample(0.140) == pytest.approx(0.295)
    assert rtx.rttvar == pytest.approx(0.0475)
    assert rtx.srtt == pytest.approx(0.105)


def test_backoff_exponencial_com_teto_e_esgotamento():
    rtx = RetransmissionManager(timeout=0.2, max_retries=3, min_rto=0.2, max_rto=1.0)
    rtx.start()
    rtos = []
    for _ in range(3):
        rtx.backoff()
        rtos.append(rtx.rto)
    assert rtos == [0.4, 0.8, 1.0]        # dobra e trava no teto
    assert rtx.exhausted
    rtx.progress()                         # chegou ACK novo: zera as tentativas
    assert not rtx.exhausted


def test_piso_do_rto():
    rtx = RetransmissionManager(min_rto=0.2)
    assert rtx.sample(0.0003) == 0.2       # LAN: RTT de 0,3 ms não vira RTO de 1,2 ms
