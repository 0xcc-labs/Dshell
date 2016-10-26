import pytest
import pcap
from dshell import IPDecoder


class GenericDecoder(IPDecoder):
    '''generic IPDecoder strictly for test purposes'''
    def __init__(self):
        IPDecoder.__init__(
            self,
            name='generic',
            description='strictly for testing',
            filter='',
            author='bg',
        )
        self.packets = []
        self.total_bytes = 0

    def _exc(self, e):
        '''needed for testing'''
        raise e

    def packetHandler(self, ip=None):
        assert ip.proto is 'UDP'
        self.packets.append((ip.sip, ip.dip, ip.proto))
        self.total_bytes += ip.bytes


@pytest.fixture(scope='module')
def decoder():
    '''open pcap, pass data through decoder, return decoder obj'''
    d = GenericDecoder()
    for ts, pkt in pcap.pcap('./tests/pcap/dns.cap'):
        d.decode(ts, pkt)
    return d


def test_ipdecoder_number_of_packets(decoder):
    assert len(decoder.packets) == decoder.count


def test_ipdecoder_number_of_decoded_bytes(decoder):
    assert decoder.total_bytes == decoder.decodedbytes
