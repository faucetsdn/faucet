#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import os
import re
import sys
from setuptools import setup


DEFAULT_SETUP_ARGS = {
    'include_package_data': True,
    'license': 'Apache License 2.0',
    'url': 'http://FaucetSDN.org',
    'author': 'Christopher Lorier',
    'author_email': 'chris.lorier@reannz.co.nz',
    'maintainer': 'Shivaram Mysore, FaucetSDN.Org',
    'maintainer_email': 'shivaram.mysore@gmail.com, faucet-dev@list.waikato.ac.nz',
    'classifiers': [
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
    ],
}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--setup_cfg', default='faucet_setup.cfg')
    try:
        arg_split_index = sys.argv.index('--')
        faucet_args = sys.argv[arg_split_index+1:]
        sys.argv = sys.argv[:arg_split_index]
    except ValueError:
        faucet_args = sys.argv
    args, _ = parser.parse_known_args(faucet_args)

    setup_dir = os.path.dirname(__file__)
    os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__),
                                           os.pardir)))
    data_files_prefix = '/'
    if (getattr(sys, 'real_prefix', sys.prefix) != sys.prefix or
            getattr(sys, 'base_prefix', sys.prefix) != sys.prefix):
        data_files_prefix = ''
    setup_args = DEFAULT_SETUP_ARGS
    setup_args.update(eval(open(args.setup_cfg).read()))
    readme_file = setup_args['long_description']
    readme_contents = open(os.path.join(setup_dir, readme_file)).read()
    version = re.match(r'.+version: ([0-9\.]+)', readme_contents).group(1)
    requirements = open(os.path.join(setup_dir, 'requirements.txt')).readlines()
    setup_args = DEFAULT_SETUP_ARGS
    setup_args.update({
        'data_files_prefix': data_files_prefix,
        'install_requires': requirements,
        'long_description': readme_contents,
        'version': version,
    })
    setup(**setup_args)
