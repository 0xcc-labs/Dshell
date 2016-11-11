import pytest
import dshell
import pcap
from dshell.loader import (
    find_decoders, import_decoder,
    print_decoder_info, parse_bpf,
)
import StringIO


@pytest.fixture(scope='module')
def decoders():
    available_decoders = list(find_decoders())  # exhuast the generator
    decoders = []
    for importer, decoder_name in available_decoders:
        decoders.append(import_decoder(importer, decoder_name))
    return decoders


def test_list_decoders():
    available_decoders = list(find_decoders())
    decoders = [decoder for importer, decoder in available_decoders]
    assert decoders[0] == 'dshell.decoders.dns.dns'
    assert decoders[1] == 'dshell.decoders.misc.synrst'


def test_import_decoder(decoders):
    for decoder in decoders:
        assert isinstance(decoder, dshell.Decoder), 'Invalid decoder: {}'.format(decoder.__module__)


def test_print_decoder_info(decoders, capsys):
    print_decoder_info(decoders)
    out, err = capsys.readouterr()
    assert out == '''  module                                   name                           author            desc
  ---------------------------------------- ------------------------------ ---------- --- -  --------------------------------------------------
  dshell.decoders.dns.dns                  dns                            bg/twp     TCP    extract and summarize DNS queries/responses (defaults: A,AAAA,CNAME,PTR records)
  dshell.decoders.misc.synrst              synrst                         bg         TCP    detect failed attempts to connect (SYN followed by a RST/ACK)
'''
    assert err == ''


def test_parse_bpf_filter():
    no_comments_bpf = StringIO.StringIO('''port 80
or port 443
''')
    ret = parse_bpf(no_comments_bpf)
    assert ret == no_comments_bpf.getvalue()

    with_comments_bpf = StringIO.StringIO('''port 80  # this is a comment
or port 443
''')
    ret = parse_bpf(with_comments_bpf)
    assert ret == no_comments_bpf.getvalue()


def test_pcap_reader_with_filter():
    bpf = StringIO.StringIO('''port 80  # this is a comment
or port 443
''')
    filter_ = parse_bpf(bpf)
    reader = pcap.pcap('./tests/pcap/http.cap')
    reader.setfilter(filter_)
    # there are 41 packets that match this filter expression
    for i, (ts, packet) in enumerate(reader):
        pass
    assert i == 40


def test_pcap_reader_with_invalid_filter():
    bpf = StringIO.StringIO('''foo 80  # this is a comment''')
    filter_ = parse_bpf(bpf)
    reader = pcap.pcap('./tests/pcap/http.cap')
    with pytest.raises(OSError):
        reader.setfilter(filter_)
