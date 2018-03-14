#!/usr/bin/env python

from __future__ import print_function

import errno
import os
import shutil
import sys

from pkg_resources import resource_filename
from setuptools import setup

def install_configs():
    """ Install configuration files to /etc """


    dst_ryu_conf_dir = '/etc/faucet/'
    dst_ryu_conf = os.path.join(dst_ryu_conf_dir, 'ryu.conf')
    dst_faucet_conf_dir = '/etc/faucet/'
    src_ryu_conf = resource_filename(__name__, "etc/faucet/ryu.conf")
    src_faucet_conf_dir = resource_filename(__name__, "etc/faucet/")
    faucet_log_dir = '/var/log/faucet/'

    old_ryu_conf = '/etc/ryu/ryu.conf'
    old_faucet_conf_dir = '/etc/ryu/faucet/'

    try:
        if not os.path.exists(dst_ryu_conf_dir):
            print("Creating %s" % dst_ryu_conf_dir)
            os.makedirs(dst_ryu_conf_dir)
        if not os.path.isfile(dst_ryu_conf):
            if os.path.exists(old_ryu_conf) and os.path.isfile(old_ryu_conf):
                print("Migrating %s to %s" % (old_ryu_conf, dst_ryu_conf))
                shutil.copy(old_ryu_conf, dst_ryu_conf)
            else:
                print("Copying %s to %s" % (src_ryu_conf, dst_ryu_conf))
                shutil.copy(src_ryu_conf, dst_ryu_conf)
        if not os.path.exists(dst_faucet_conf_dir):
            print("Creating %s" % dst_faucet_conf_dir)
            os.makedirs(dst_faucet_conf_dir)
        for file_name in os.listdir(src_faucet_conf_dir):
            src_file = os.path.join(src_faucet_conf_dir, file_name)
            dst_file = os.path.join(dst_faucet_conf_dir, file_name)
            alt_src = os.path.join(old_faucet_conf_dir, file_name)
            if os.path.isfile(dst_file):
                continue
            elif os.path.isfile(alt_src):
                print("Migrating %s to %s" % (alt_src, dst_file))
                shutil.copy(alt_src, dst_file)
            elif os.path.isfile(src_file):
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

setup(
    name='faucet',
    setup_requires=['pbr>=1.9', 'setuptools>=17.1'],
    pbr=True
)

if 'install' in sys.argv or 'bdist_wheel' in sys.argv:
    if os.getenv("DEBINSTALL") is None or (os.getenv("DEBINSTALL") is not None and int(os.environ['DEBINSTALL']) < 1):
        install_configs()
