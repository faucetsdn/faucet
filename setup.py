#!/usr/bin/env python

from __future__ import print_function

import errno
import io
import os
import re
import shutil
import sys

from pkg_resources import resource_filename
from setuptools import setup

def parse_version():
    """ Parse version from README.rst """
    setup_dir = os.path.dirname(__file__)
    readme_contents = io.open(os.path.join(setup_dir, 'README.rst'), encoding="utf-8").read()
    faucet_version = re.match(r'.+version: ([0-9\.]+)', readme_contents).group(1)
    return faucet_version

def install_configs():
    """ Install configuration files to /etc """

    dst_ryu_conf_dir = '/etc/ryu/'
    dst_ryu_conf = os.path.join(dst_ryu_conf_dir, 'ryu.conf')
    dst_faucet_conf_dir = '/etc/ryu/faucet/'
    src_ryu_conf = resource_filename(__name__, "etc/ryu/ryu.conf")
    src_faucet_conf_dir = resource_filename(__name__, "etc/ryu/faucet/")
    faucet_log_dir = '/var/log/ryu/faucet/'

    try:
        if not os.path.exists(dst_ryu_conf_dir):
            print("Creating %s" % dst_ryu_conf_dir)
            os.makedirs(dst_ryu_conf_dir)
        if not os.path.isfile(dst_ryu_conf):
            print("Copying %s to %s" % (src_ryu_conf, dst_ryu_conf))
            shutil.copy(src_ryu_conf, dst_ryu_conf)
        if not os.path.exists(dst_faucet_conf_dir):
            print("Creating %s" % dst_faucet_conf_dir)
            os.makedirs(dst_faucet_conf_dir)
        for file_name in os.listdir(src_faucet_conf_dir):
            src_file = os.path.join(src_faucet_conf_dir, file_name)
            dst_file = os.path.join(dst_faucet_conf_dir, file_name)
            if os.path.isfile(src_file) and not os.path.isfile(dst_file):
                print("Copying %s to %s" % (src_file, dst_file))
                shutil.copy(src_file, dst_file)
        if not os.path.exists(faucet_log_dir):
            print("Creating %s" % faucet_log_dir)
            os.makedirs(faucet_log_dir)
    except OSError as exception:
        if exception.errno == errno.EACCES:
            print("Permission denied creating %s, skipping copying configs"
                  % exception.filename)
        else:
            raise

os.environ["PBR_VERSION"] = parse_version()

setup(
    name='faucet',
    setup_requires=['pbr>=1.9', 'setuptools>=17.1'],
    pbr=True
)

if 'install' in sys.argv or 'bdist_wheel' in sys.argv:
    install_configs()
