#!/usr/bin/env python

import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


install_requires = [
    'pycrypto==2.6.1',
    'pygeoip==0.3.2',
    'pypcap==1.1.5',
    'dpkt==1.8.8',
    'IPy==0.83',
    'elasticsearch==5.0.0',
    'pytest==2.8.7',
    'pytest-cov==2.2.1',
    'pytest-pep8==1.0.6',
    'coverage==4.0.3',
]


setup(
    name='dshell',
    version='3.0.0',
    description='An extensible network forensic analysis framework.',
    author='wglodek',
    author_email='wglodek@breakpoint-labs.com',
    packages=find_packages(),
    install_requires=install_requires,
    license='MIT',
    zip_safe=False,
    test_suite='tests',
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ),
)
