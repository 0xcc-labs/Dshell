class DshellException(Exception):
    '''generic Dshell exception'''


class MissingDecoder(DshellException):
    '''missing decoder'''


class InvalidDecoderOption(DshellException):
    '''optiondict error in the decoder'''
