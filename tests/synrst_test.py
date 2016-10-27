import pytest
import pcap
from dshell.decoders.misc.synrst import DshellDecoder


def test_synrst_decoder():
    assert DshellDecoder() is not None


@pytest.fixture(scope='module')
def decoder():
    '''open pcap, pass data through decoder, return decoder obj'''
    def new_exc(e):
        raise e

    def new_alert(*args, **kwargs):
        pass

    d = DshellDecoder()
    d._exc = new_exc
    d.alert = new_alert
    for ts, pkt in pcap.pcap('./tests/pcap/http.cap'):
        d.decode(ts, pkt)
    return d


def test_synrst_tracking(decoder):
    assert decoder.tracker == {
        '145.254.160.237:3372:951057939:65.208.228.223:80': '',
    }
