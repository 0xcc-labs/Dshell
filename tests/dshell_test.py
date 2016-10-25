import pytest
from dshell import IPDecoder
import pcap
from dpkt.ethernet import Ethernet


@pytest.fixture
def pcap_file_ethernet():
    return pcap.pcap('./tests/pcap/dns.cap')


def test_IP_decoder():
    obj = IPDecoder()
    assert obj is not None
    assert obj.filter is ''
    assert obj.l2decoder is Ethernet
    assert not obj.isPacketHandlerPresent


def test_pcap_reader_packet_count(pcap_file_ethernet):
    for i, (ts, packet) in enumerate(pcap_file_ethernet):
        pass
    assert i == 37  # 38 packets in sample pcap file


def test_pcap_reader_layer2_Ethernet(pcap_file_ethernet):
    for ts, packet in pcap_file_ethernet:
        packet_len = len(packet)
        pkt = Ethernet(packet)
        assert len(pkt) == packet_len
        assert isinstance(pkt, Ethernet)
