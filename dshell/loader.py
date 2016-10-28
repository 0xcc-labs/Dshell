import pkgutil
import decoders


def find_decoders():
    '''find all available decoders'''
    for module_loader, name, ispkg in pkgutil.walk_packages(path=decoders.__path__, prefix=decoders.__name__ + '.'):
        if not ispkg:
            yield module_loader, name


def import_decoder(importer, module_name):
    '''import a specific decoder'''
    return importer.find_module(module_name).load_module(module_name).DshellDecoder()


def print_decoder_info(decoders):
    '''print decoders with additional information'''
    fmt_str = '  %-40s %-30s %-10s %s %1s  %s'
    print fmt_str % ('module', 'name', 'author', '   ', ' ', 'desc')
    print fmt_str % ('-' * 40, '-' * 30, '-' * 10, '---', '-', '-' * 50)
    dtype = 'RAW'
    for decoder in decoders:
        dtype = 'IP ' if hasattr(decoder, 'IP') else dtype
        dtype = 'UDP' if hasattr(decoder, 'UDP') else dtype
        dtype = 'TCP' if hasattr(decoder, 'TCP') else dtype
        print fmt_str % (
            decoder.__module__,
            decoder.name,
            decoder.author,
            dtype,
            '+' if decoder.chainable else '',
            decoder.description
        )


def parse_bpf(bpf_fh):
    '''parse bpf filter'''
    filter_ = ''
    for line in bpf_fh:
        if '#' in line:
            line = line.split('#')[0].rstrip() + '\n'
        filter_ += line
    return filter_
