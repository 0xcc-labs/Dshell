import pytest
from dshell.util import xor, decode_base64
from dshell.exceptions import DshellException


def test_xor_with_one_byte_key():
    s = 'AAAA'
    k = 0x20
    assert xor(s, k) == 'aaaa'


def test_xor_with_multibyte_key():
    s = 'AAAA'
    k = 0x2020
    with pytest.raises(ValueError):
        xor(s, k) == 'aaaa'


def test_decode_base64_with_standard_alphabet():
    intext = 'SGVsbG8gd29ybGQ='  # base64('Hello world'), default alphabet
    assert decode_base64(intext) == 'Hello world\x00'


def test_decode_base64_with_nonstandard_alphabet():
    intext = '+v5KPvX7UrloPv1A'
    assert decode_base64(intext, alphabet='QpaZIivj4ndG=H021y+NO5RST/xPgUz67FMhYq8b3wemKfkJLBocCDrs9VtWXlEuA') == 'Hello world@'


def test_decode_base64_with_invalid_alphabet():
    with pytest.raises(DshellException):
        decode_base64('foo', alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYAabcdefghijklmnopqrstuvwxyz0123456789+/')
