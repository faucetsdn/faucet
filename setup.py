#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
from os import path
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

    # allow setup.py to be run from any path
    os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__),
                                           os.pardir)))

    setup(
        name='ryu-faucet',
        version='0.31',
        packages=['ryu_faucet'],
        package_dir={'ryu_faucet': 'src/ryu_faucet'},
        data_files=[('/etc/ryu/faucet', ['src/cfg/etc/ryu/faucet/gauge.conf',
                                         'src/cfg/etc/ryu/faucet/faucet.yaml']),
                    ('/etc/ryu/faucet/upstart', ['src/cfg/etc/ryu/faucet/upstart/gauge.conf',
                                         'src/cfg/etc/ryu/faucet/upstart/faucet.conf',
                                         'src/cfg/etc/ryu/faucet/upstart/gauge',
                                         'src/cfg/etc/ryu/faucet/upstart/faucet'])
                    ],
        include_package_data=True,
        install_requires=['ryu', 'pyyaml', 'influxdb', 'ipaddress'],
        license='Apache License 2.0',
        description='Ryu application to perform Layer 2 switching with VLANs.',
        long_description=README,
        url='http://onfsdn.github.io/faucet',
        author='Christopher Lorier',
        author_email='chris.lorier@reannz.co.nz',
        maintainer='Shivaram Mysore, ONFSDN.Org',
        maintainer_email='shivaram.mysore@gmail.com, faucet-dev@OpenflowSDN.Org',
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Environment :: Console',
            'Framework :: Buildout',
            'Intended Audience :: Developers',
            'Intended Audience :: Information Technology',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: Apache Software License',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3.5',
            'Topic :: System :: Networking',
        ],)
