from dshell.util import xor


def test_xor():
    s = 'AAAA'
    k = 0x20
    assert xor(s, k) == 'aaaa'
