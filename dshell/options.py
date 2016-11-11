import argparse
import tempfile
import sys
from .exceptions import InvalidDecoderOption


class DecoderOptionParser(argparse.ArgumentParser):
    '''custom subclass to parse decoder specific options'''
    def error(self, message):
        raise InvalidDecoderOption


def get_decoder_options(decoder, unknown_args):
    '''get decoder specific options from the decoder object itself'''
    parser = DecoderOptionParser(
        description=decoder.name,
    )
    for arg, optargs in decoder.optiondict.iteritems():
        arg_name = '{}_{}'.format(decoder.name, arg)
        parser.add_argument(
            '--{}'.format(arg_name),
            dest=arg,
            action=optargs.get('action'),
            help=optargs.get('help'),
        )
    args = parser.parse_args(unknown_args)
    return args


def get_argument_parser():
    '''build Dshell ArgumentParser'''
    parser = argparse.ArgumentParser(
        description='An extensible network forensic analysis framework',
    )

    parser.add_argument(
        '-d', '--decoder',
        dest='decoder',
        help='Use a specific decoder'
    )

    parser.add_argument(
        'input_files',
        nargs=argparse.REMAINDER,
        help='Pcap files to process',
    )

    parser.add_argument(
        '-l', '--list',
        dest='ls',
        action='store_true',
        help='List all available decoders',
    )

    parser.add_argument(
        '-C', '--config',
        dest='config',
        help='Specify config.ini file'
    )

    parser.add_argument(
        '--tmpdir',
        dest='tmpdir',
        default=tempfile.gettempdir(),
        help='Alternate temp directory for use '
             'when processing compressed pcap files'
    )

    parser.add_argument(
        '-r', '--recursive',
        dest='recursive',
        action='store_true',
        help='Recursively process all pcap files '
             'under the input directory',
    )

    parser_group_multiproc = parser.add_argument_group(
        title='Multiprocessing options'
    )

    parser_group_multiproc.add_argument(
        '-p', '--parallel',
        dest='parallel',
        action='store_true',
        help='process multiple files in parallel',
    )

    parser_group_multiproc.add_argument(
        '-t', '--threaded',
        dest='threaded',
        action='store_true',
        help='process multiple files using threads',
    )

    parser_group_multiproc.add_argument(
        '-n', '--nprocs',
        dest='numprocs',
        type=int,
        default=4,
        help='number of simultaneous processes',
    )

    parser_group_input = parser.add_argument_group(
        title='Input options'
    )

    parser_group_input.add_argument(
        '-i', '--interface',
        dest='interface',
        help='listen on a specific interface',
    )

    parser_group_input.add_argument(
        '-c', '--count',
        dest='count',
        type=int,
        default=0,
        help='number of packets to process',
    )

    parser_group_input.add_argument(
        '-f', '--bpf',
        dest='bpf',
        help='replace default decoder BPF filter',
    )

    parser_group_input.add_argument(
        '--nofilterfn',
        dest='nofilterfn',
        action='store_true',
        help='Set filterfn to pass-thru'
    )

    parser_group_input.add_argument(
        '-F',
        dest='file_filter',  # TODO: this is a change from the original
        help='Read BPF expressions from a file.'
    )

    parser_group_input.add_argument(
        '--ebpf',
        dest='ebpf',
        help='BPF filter to exclude traffic, extends other filters',
    )

    parser_group_input.add_argument(
        '--no-vlan',
        dest='novlan',
        action='store_true',
        help='Do not examine traffic which has VLAN headers present',
    )

    parser_group_input.add_argument(
        '--layer2',
        dest='layer2',
        default='ethernet.Ethernet',
        help='Select the layer-2 protocol module',
    )

    parser_group_input.add_argument(
        '--strip',
        dest='strip_layers',
        default=0,  # TODO: look into this
        help='Extra data-link layers to strip'
    )

    parser_group_output = parser.add_argument_group(
        title='Output options'
    )

    parser_group_output.add_argument(
        '-o', '--outfile',
        dest='outfile',
        help='Write output to the OUTFILE. '
             'Additional output can be set with KEYWORD=Value.'
             '\tmode=<w: write (default), a: append,'
             ' noclobber: do not overwrite, use an'
             ' OUTFILE.1 (.2,.3) file if file(s) exists\n'
             '\tpcap=PCAPFILE to write packets to a PCAP file\n'
             '\tsession=SESSION to write session text\n'
             '\tdirection=data direction to write (c,s,both,split)'
    )

    parser_group_output.add_argument(
        '--nobuf',
        dest='no_buffer',  # TODO: changed the variable name
        action='store_true',
        help='Turn off output buffering',
    )

    parser_group_output.add_argument(
        '-w', '--session',
        dest='session',
        help='Write session file (same as -o session=...)'
    )

    parser_group_output.add_argument(
        '-W', '--pcap',
        dest='pcap',
        help='Write output as decoded packets to PCAP'
             ' (same as -o pcap=...)'
    )

    # Not implementing output db option

    parser_group_output.add_argument(
        '--oformat',
        dest='oformat',
        default='output',
        help='Define the output format'
    )

    parser_group_output.add_argument(
        '-x', '--extra',
        dest='oextra',
        action='store_true',
        help='Output a lot of extra information'
    )

    parser_group_output.add_argument(
        '-O', '--output',
        dest='output',
        help='Use a custom output module. Supply'
             '"modulename,option=value,..."'
    )

    parser_group_logging = parser.add_argument_group(
        title='Logging options'
    )

    parser_group_logging.add_argument(
        '-L', '--logfile',
        dest='logfile',
        help='Log to file'
    )

    parser_group_logging.add_argument(
        '--debug',
        dest='debug',
        action='store_true',
        help='debug logging (debug may also affect decoding behavior)'
    )

    parser_group_logging.add_argument(
        '-v', '--verbose',
        dest='verbose',
        action='store_true',
        help='verbose logging'
    )

    parser_group_logging.add_argument(
        '-q', '--quiet',
        dest='quiet',
        action='store_true',
        help='practically zero logging'
    )

    return parser


def parse_extra_decoder_options(largs):
    '''parse decoder specific options that follow "--"'''
    decoder_args = []
    args = []
    extra_args = False
    for x in largs:
        if x == '--':
            extra_args = True
            continue
        if extra_args:
            decoder_args.append(x)
        else:
            args.append(x)
    return args


def read_config(config_filename):
    '''read config options from a file'''
    import ConfigParser
    config = ConfigParser.ConfigParser()
    config.read(config_filename)

    options = {}

    for s in config.sections():
        # this is the main section, set the options
        if s.lower() == 'dshell':
            for k, v in config.items(s, raw=True):
                options[k] = v
    return options


if __name__ == '__main__':
    p = get_argument_parser()
    args = p.parse_args(sys.argv[1:])
    print args
