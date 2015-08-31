from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

setup(
    name='faucet',
    version='0.1',

    description='Ryu app to perform Layer 2 switching with VLANs.',

    author='Christopher Lorier',
    author_email='chris.lorier@reannz.co.nz',

    license='Apache License 2.0',

    packages=find_packages(exclude=['tests*']),

    install_requires=['ryu', 'pyyaml'],
)
