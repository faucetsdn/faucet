#!/usr/bin/python

import os
import re

from setuptools import setup

setup_dir = os.path.dirname(__file__)
readme_contents = open(os.path.join(setup_dir, 'README.rst')).read()
faucet_version = re.match(r'.+version: ([0-9\.]+)', readme_contents).group(1)
os.environ["PBR_VERSION"] = faucet_version

setup(
    name='faucet',
    setup_requires=['pbr>=1.9', 'setuptools>=17.1'],
    pbr=True
)
