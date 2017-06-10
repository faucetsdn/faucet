#!/usr/bin/env python

"""Mininet tests for FAUCET.

 * must be run as root
 * you can run a specific test case only, by adding the class name of the test
   case to the command. Eg ./faucet_mininet_test.py FaucetUntaggedIPv4RouteTest

It is strong recommended to run these tests via Docker, to ensure you have
all dependencies correctly installed. See ../docs/.
"""

# pylint: disable=missing-docstring
# pylint: disable=unused-wildcard-import

import collections
import glob
import inspect
import os
import sys
import getopt
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

import yaml

from concurrencytest import ConcurrentTestSuite, fork_for_tests
from mininet.log import setLogLevel
from mininet.clean import Cleanup
from packaging import version

import faucet_mininet_test_util

# pylint: disable=wildcard-import
from faucet_mininet_test_unit import *


EXTERNAL_DEPENDENCIES = (
    ('ryu-manager', ['--version'],
     'ryu-manager', r'ryu-manager (\d+\.\d+)\n', "4.9"),
    ('ovs-vsctl', ['--version'], 'Open vSwitch',
     r'ovs-vsctl\s+\(Open vSwitch\)\s+(\d+\.\d+)\.\d+\n', "2.3"),
    ('tcpdump', ['-h'], 'tcpdump',
     r'tcpdump\s+version\s+(\d+\.\d+)\.\d+\n', "4.5"),
    ('nc', [], 'nc from the netcat-openbsd', '', 0),
    ('vconfig', [], 'the VLAN you are talking about', '', 0),
    ('2to3', ['--help'], 'Usage: 2to3', '', 0),
    ('fuser', ['-V'], r'fuser \(PSmisc\)',
     r'fuser \(PSmisc\) (\d+\.\d+)\n', "22.0"),
    ('mn', ['--version'], r'\d+\.\d+.\d+',
     r'(\d+\.\d+).\d+', "2.2"),
    ('exabgp', ['--version'], 'ExaBGP',
     r'ExaBGP : (\d+\.\d+).\d+', "3.4"),
    ('pip', ['show', 'influxdb'], 'influxdb',
     r'Version:\s+(\d+\.\d+)\.\d+', "3.0"),
    ('pylint', ['--version'], 'pylint',
     r'pylint (\d+\.\d+).\d+,', "1.6"),
    ('curl', ['--version'], 'libcurl',
     r'curl (\d+\.\d+).\d+', "7.3"),
    ('ladvd', ['-h'], 'ladvd',
     r'ladvd version (\d+\.\d+)\.\d+', "1.1"),
    ('iperf', ['--version'], 'iperf',
     r'iperf version (\d+\.\d+)\.\d+', "2.0"),
    ('fping', ['-v'], 'fping',
     r'fping: Version (\d+\.\d+)', "3.13"),
    ('rdisc6', ['-V'], 'ndisc6',
     r'ndisc6.+tool (\d+\.\d+)', "1.0"),
)

# Must pass with 0 lint errors
FAUCET_LINT_SRCS = glob.glob(
        os.path.join(faucet_mininet_test_util.FAUCET_DIR, '*py'))
FAUCET_TEST_LINT_SRCS = glob.glob(
    os.path.join(os.path.dirname(__file__), 'faucet_mininet_test*py'))

# Maximum number of parallel tests to run at once
MAX_PARALLEL_TESTS = 6

# see hw_switch_config.yaml for how to bridge in an external hardware switch.
HW_SWITCH_CONFIG_FILE = 'hw_switch_config.yaml'
CONFIG_FILE_DIRS = ['/etc/ryu/faucet', './']
REQUIRED_TEST_PORTS = 4


def import_hw_config():
    """Import configuration for physical switch testing."""
    for config_file_dir in CONFIG_FILE_DIRS:
        config_file_name = os.path.join(config_file_dir, HW_SWITCH_CONFIG_FILE)
        if os.path.isfile(config_file_name):
            break
    if os.path.isfile(config_file_name):
        print('Using config from %s' % config_file_name)
    else:
        print('Cannot find %s in %s' % (HW_SWITCH_CONFIG_FILE, CONFIG_FILE_DIRS))
        sys.exit(-1)
    try:
        with open(config_file_name, 'r') as config_file:
            config = yaml.load(config_file)
    except IOError:
        print('Could not load YAML config data from %s' % config_file_name)
        sys.exit(-1)
    if 'hw_switch' in config:
        hw_switch = config['hw_switch']
        if not isinstance(hw_switch, bool):
            print('hw_switch must be a bool: ' % hw_switch)
            sys.exit(-1)
        if not hw_switch:
            return None
        required_config = {
            'dp_ports': (dict,),
            'cpn_intf': (str,),
            'dpid': (long, int),
            'of_port': (int,),
            'gauge_of_port': (int,),
        }
        for required_key, required_key_types in list(required_config.items()):
            if required_key not in config:
                print('%s must be specified in %s to use HW switch.' % (
                    required_key, config_file_name))
                sys.exit(-1)
            required_value = config[required_key]
            key_type_ok = False
            for key_type in required_key_types:
                if isinstance(required_value, key_type):
                    key_type_ok = True
                    break
            if not key_type_ok:
                print('%s (%s) must be %s in %s' % (
                    required_key, required_value,
                    required_key_types, config_file_name))
                sys.exit(1)
        dp_ports = config['dp_ports']
        if len(dp_ports) != REQUIRED_TEST_PORTS:
            print('Exactly %u dataplane ports are required, '
                  '%d are provided in %s.' %
                  (REQUIRED_TEST_PORTS, len(dp_ports), config_file_name))
        return config
    else:
        return None


def check_dependencies():
    """Verify dependant libraries/binaries are present with correct versions."""
    print('Checking library/binary dependencies')
    for (binary, binary_get_version, binary_present_re,
         binary_version_re, binary_minversion) in EXTERNAL_DEPENDENCIES:
        binary_args = [binary] + binary_get_version
        required_binary = 'required binary/library %s' % (
            ' '.join(binary_args))
        try:
            proc = subprocess.Popen(
                binary_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            proc_out, proc_err = proc.communicate()
            binary_output = proc_out
            if proc_err is not None:
                binary_output += proc_err
        except subprocess.CalledProcessError:
            # Might have run successfully, need to parse output
            pass
        except OSError:
            print('could not run %s' % required_binary)
            return False
        present_match = re.search(binary_present_re, binary_output)
        if not present_match:
            print('%s not present or did not return expected string %s' % (
                required_binary, binary_present_re))
            return False
        if binary_version_re:
            version_match = re.search(binary_version_re, binary_output)
            if version_match is None:
                print('could not get version from %s (%s)' % (
                    required_binary, binary_output))
                return False
            try:
                binary_version = version_match.group(1)
            except ValueError:
                print('cannot parse version %s for %s' % (
                    version_match, required_binary))
                return False
            if version.parse(binary_version) < version.parse(binary_minversion):
                print('%s version %s is less than required version %s' % (
                    required_binary, binary_version, binary_minversion))
                return False
    return True


def lint_check():
    """Run pylint on required source files."""
    print('Running pylint checks')
    for faucet_src in FAUCET_LINT_SRCS + FAUCET_TEST_LINT_SRCS:
        ret = subprocess.call(['pylint', '--rcfile=/dev/null', '-E', faucet_src])
        if ret:
            print(('pylint of %s returns an error' % faucet_src))
            return False
    for faucet_src in FAUCET_LINT_SRCS:
        output_2to3 = subprocess.check_output(
            ['2to3', '--nofix=import', faucet_src],
            stderr=open(os.devnull, 'wb'))
        if output_2to3:
            print(('2to3 of %s returns a diff (not python3 compatible)' % faucet_src))
            print(output_2to3)
            return False
    return True


def make_suite(tc_class, hw_config, root_tmpdir, ports_sock):
    """Compose test suite based on test class names."""
    testloader = unittest.TestLoader()
    testnames = testloader.getTestCaseNames(tc_class)
    suite = unittest.TestSuite()
    for name in testnames:
        suite.addTest(tc_class(name, hw_config, root_tmpdir, ports_sock))
    return suite


def pipeline_superset_report(root_tmpdir):
    ofchannel_logs = glob.glob(
        os.path.join(root_tmpdir, '*/ofchannel.log'))
    match_re = re.compile(
        r'^.+types table: (\d+) match: (.+) instructions: (.+) actions: (.+)')
    table_matches = collections.defaultdict(set)
    table_instructions = collections.defaultdict(set)
    table_actions = collections.defaultdict(set)
    for log in ofchannel_logs:
        for log_line in open(log).readlines():
            match = match_re.match(log_line)
            if match:
                table, matches, instructions, actions = match.groups()
                table = int(table)
                table_matches[table].update(eval(matches))
                table_instructions[table].update(eval(instructions))
                table_actions[table].update(eval(actions))
    print('')
    for table in sorted(table_matches):
        print('table: %u' % table)
        print('  matches: %s' % sorted(table_matches[table]))
        print('  table_instructions: %s' % sorted(table_instructions[table]))
        print('  table_actions: %s' % sorted(table_actions[table]))


def expand_tests(requested_test_classes, excluded_test_classes,
                 hw_config, root_tmpdir, ports_sock, serial):
    total_tests = 0
    sanity_tests = unittest.TestSuite()
    single_tests = unittest.TestSuite()
    parallel_tests = unittest.TestSuite()
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if not inspect.isclass(obj):
            continue
        if requested_test_classes and name not in requested_test_classes:
            continue
        if excluded_test_classes and name in excluded_test_classes:
            continue
        if name.endswith('Test') and name.startswith('Faucet'):
            # TODO: hardware testing should have a way to configure
            # which switch in a string is the hardware switch to test.
            if re.search(r'Faucet.*String', name) and hw_config is not None:
                print(
                    'skipping %s as string tests not supported for hardware' % name)
                continue
            print('adding test %s' % name)
            test_suite = make_suite(obj, hw_config, root_tmpdir, ports_sock)
            if name.startswith('FaucetSanity'):
                sanity_tests.addTest(test_suite)
            else:
                if serial or name.startswith('FaucetSingle'):
                    single_tests.addTest(test_suite)
                    total_tests += 1
                else:
                    parallel_tests.addTest(test_suite)
                    total_tests += 1
    return (total_tests, sanity_tests, single_tests, parallel_tests)


def run_test_suites(sanity_tests, single_tests, parallel_tests):
    all_successful = False
    sanity_runner = unittest.TextTestRunner(verbosity=255, failfast=True)
    sanity_result = sanity_runner.run(sanity_tests)
    if sanity_result.wasSuccessful():
        print('running %u tests in parallel and %u tests serial' % (
            parallel_tests.countTestCases(), single_tests.countTestCases()))
        results = []
        if parallel_tests.countTestCases():
            max_parallel_tests = min(parallel_tests.countTestCases(), MAX_PARALLEL_TESTS)
            parallel_runner = unittest.TextTestRunner(verbosity=255)
            parallel_suite = ConcurrentTestSuite(
                parallel_tests, fork_for_tests(max_parallel_tests))
            results.append(parallel_runner.run(parallel_suite))
        # TODO: Tests that are serialized generally depend on hardcoded ports.
        # Make them use dynamic ports.
        if single_tests.countTestCases():
            single_runner = unittest.TextTestRunner(verbosity=255)
            results.append(single_runner.run(single_tests))
        all_successful = True
        for result in results:
            if not result.wasSuccessful():
                all_successful = False
                print(result.printErrors())
    else:
        print('sanity tests failed - test environment not correct')
    return all_successful


def start_port_server(root_tmpdir):
    ports_sock = os.path.join(root_tmpdir, 'ports-server')
    ports_server = threading.Thread(
        target=faucet_mininet_test_util.serve_ports, args=(ports_sock,))
    ports_server.setDaemon(True)
    ports_server.start()
    for _ in range(10):
        if os.path.exists(ports_sock):
            break
        time.sleep(1)
    if not os.path.exists(ports_sock):
        print('ports server did not start (%s not created)' % ports_sock)
        sys.exit(-1)
    return ports_sock


def run_tests(requested_test_classes,
              excluded_test_classes,
              keep_logs,
              serial,
              hw_config):
    """Actually run the test suites, potentially in parallel."""
    if hw_config is not None:
        print('Testing hardware, forcing test serialization')
        serial = True
    root_tmpdir = tempfile.mkdtemp(prefix='faucet-tests-')
    ports_sock = start_port_server(root_tmpdir)
    total_tests, sanity_tests, single_tests, parallel_tests = expand_tests(
        requested_test_classes, excluded_test_classes,
        hw_config, root_tmpdir, ports_sock, serial)
    all_successful = run_test_suites(
        sanity_tests, single_tests, parallel_tests)
    pipeline_superset_report(root_tmpdir)
    os.remove(ports_sock)
    if not keep_logs and all_successful:
        shutil.rmtree(root_tmpdir)
    if not all_successful:
        sys.exit(-1)


def parse_args():
    """Parse command line arguments."""
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            'cknsx:',
            ['clean', 'nocheck', 'keep_logs', 'serial'])
    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    clean = False
    keep_logs = False
    nocheck = False
    serial = False
    excluded_test_classes = []

    for opt, arg in opts:
        if opt in ('-c', '--clean'):
            clean = True
        if opt in ('-n', '--nocheck'):
            nocheck = True
        if opt in ('-k', '--keep_logs'):
            keep_logs = True
        if opt in ('-s', '--serial'):
            serial = True
        if opt == '-x':
            excluded_test_classes.append(arg)

    return (args, clean, keep_logs, nocheck, serial, excluded_test_classes)


def test_main():
    """Test main."""
    setLogLevel('info')
    args, clean, keep_logs, nocheck, serial, excluded_test_classes = parse_args()

    if clean:
        print('Cleaning up test interfaces, processes and openvswitch '
              'configuration from previous test runs')
        Cleanup.cleanup()
        sys.exit(0)
    if nocheck:
        print('Skipping dependencies/lint checks')
    else:
        if not check_dependencies():
            print('dependency check failed. check required library/binary '
                  'list in header of this script')
            sys.exit(-1)
        if not lint_check():
            print('pylint must pass with no errors')
            sys.exit(-1)
    hw_config = import_hw_config()
    run_tests(args, excluded_test_classes, keep_logs, serial, hw_config)


if __name__ == '__main__':
    test_main()
