#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
from os import path
from setuptools import setup
import sys

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

    # allow setup.py to be run from any path
    os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__),
                                           os.pardir)))

    data_files_prefix = '/'
    if (getattr(sys, "real_prefix", sys.prefix) != sys.prefix or
        getattr(sys, "base_prefix", sys.prefix) != sys.prefix):
        data_files_prefix = ''

    setup(
        name='ryu-faucet',
        version='1.2.1',
        packages=['ryu_faucet'],
        package_dir={'ryu_faucet': 'src/ryu_faucet'},
        ## Temp Fix for v1.2 to not use data_files_prefix as we have package install issues.
        #data_files=[(data_files_prefix + 'etc/ryu/faucet',
        data_files=[
            ('/etc/ryu', [
                'src/cfg/etc/ryu/ryu.conf'
            ]),
            ('/etc/ryu/faucet', [
                'src/cfg/etc/ryu/faucet/faucet.yaml-dist',
                'src/cfg/etc/ryu/faucet/gauge.yaml-dist'
            ]),
            ('/etc/ryu/faucet/examples', [
                'src/cfg/etc/ryu/faucet/examples/faucet_lagopus.yaml',
                'src/cfg/etc/ryu/faucet/examples/faucet_zodiacfx.yaml',
                'src/cfg/etc/ryu/faucet/examples/faucet_ovs.yaml',
                'src/cfg/etc/ryu/faucet/examples/faucet_demo_step1.yaml',
                'src/cfg/etc/ryu/faucet/examples/faucet_demo_step2.yaml',
                'src/cfg/etc/ryu/faucet/examples/faucet_demo_step3.yaml'
            ])
        ],
        include_package_data=True,
        install_requires=['ryu', 'pyyaml', 'influxdb', 'ipaddr', 'concurrencytest', 'couchdb', 'networkx'],
        license='Apache License 2.0',
        description='Faucet is an Application for Ryu Openflow Controller to enable drop-in replacement for standard or legacy L2/L3 switch with extra SDN based functionality',
        long_description=README,
        url='http://onfsdn.github.io/faucet',
        author='Christopher Lorier',
        author_email='chris.lorier@reannz.co.nz',
        maintainer='Shivaram Mysore, ONFSDN.Org',
        maintainer_email='shivaram.mysore@gmail.com, faucet-dev@OpenflowSDN.Org',
        classifiers=[
            'Development Status :: 5 - Production/Stable',
            'Environment :: Console',
            'Framework :: Buildout',
            'Intended Audience :: Developers',
            'Intended Audience :: Information Technology',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: Apache Software License',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Programming Language :: Python :: 2.7',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.2',
            'Topic :: System :: Networking',
        ],)
