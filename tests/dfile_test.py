import pytest
from dshell import dfile


@pytest.fixture(scope='module')
def data_file_obj():
    return dfile.dfile(data='AAAA')


def test_dfile_initializations(data_file_obj):
    assert data_file_obj is not None


def test_dfile_local_filename_generation(data_file_obj):
    orig = 'file:v2'
    fname = data_file_obj.generate_local_filename(orig)
    assert fname.endswith('file_v2')
