import pytest
from dshell.options import get_argument_parser


@pytest.fixture(scope='module')
def parser():
    return get_argument_parser()


def test_default_options(parser):
    args, unknown = parser.parse_known_args([])
    assert vars(args) == {
        'config': None,
        'file_filter': None,
        'interface': None,
        'oextra': False,
        'outfile': None,
        'novlan': False,
        'threaded': False,
        'verbose': False,
        'nofilterfn': False,
        'recursive': False,
        'ebpf': None,
        'strip_layers': 0,
        'bpf': None,
        'logfile': None,
        'decoder': None,
        'oformat': 'output',
        'debug': False,
        'output': None,
        'parallel': False,
        'input_files': [],
        'count': 0,
        'numprocs': 4,
        'layer2': 'ethernet.Ethernet',
        'no_buffer': False,
        'ls': False,
        'tmpdir': '/var/folders/tf/r3m984fs5kx5njhdc_3bm49c0000gn/T',
        'pcap': None,
        'quiet': False,
        'session': None
    }
