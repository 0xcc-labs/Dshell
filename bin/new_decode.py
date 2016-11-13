import logging
import pcap
import sys
from dshell import options, loader, exceptions
import pdb


def run_decoder(decoder, input_files):
    for input_file in input_files:
        print input_file


def main(args, extra_args):
    global log 

    # setup logging
    logger = logging.getLogger('dshell')
    if args.debug:
        level = logging.DEBUG
    elif args.verbose:
        level = logging.INFO
    else:
        level = logging.FATAL
    logging.basicConfig(filename=args.logfile, level=level)

    logger.debug(args)
    logger.debug(extra_args)

    if args.ls:
        loader.list_available_decoders()
        return

    if args.decoder:
        decoders = {}
        for importer, name in loader.find_decoders():
            decoders[name] = importer

        decoder = None
        # TODO: This currently supports only a single decoder
        for decoder_name in args.decoder.split('+')[::-1]:
            try:
                k = loader.decoder_lookup_helper(decoder_name, decoders.keys())
            except exceptions.MissingDecoder:
                # TODO: log error
                continue
            decoder = loader.import_decoder(decoders[k], k)  # import the actual decoder

    # a decoder should be selected at this point
    assert decoder is not None

    # parse decoder-specific options
    if decoder.optiondict:
        decoder_options = options.get_decoder_options(decoder, extra_args)
        decoder.__dict__.update(vars(decoder_options))

    # set up decoder specific outputter
    outputter = loader.load_outputter(args.oformat)
    decoder.out = outputter
    decoder.out.logger = logging.getLogger(decoder.name)
    decoder.out.setup()

    logger.debug(args.input_files)
    for input_file in args.input_files:
        decoder.capture = pcap.pcap(input_file)
        for ts, pkt in decoder.capture:
            logger.debug('decoding a packet')
            decoder.decode(ts, pkt)


if __name__ == '__main__':
    parser = options.get_argument_parser()
    args, unknown = parser.parse_known_args(sys.argv[1:])
    main(args, unknown)
