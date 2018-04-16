#!/usr/bin/env python

"""Mininet test runner

 * must be run as root
 * you can run a specific test case only, by adding the class name of the test
   case to the command. Eg ./mininet_test.py FaucetUntaggedIPv4RouteTest

It is strongly recommended to run these tests via Docker, to ensure you have
all dependencies correctly installed. See ../docs/.
"""

# pylint: disable=missing-docstring

import collections
import copy
import glob
import inspect
import os
import sys
import getopt
import multiprocessing
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

import yaml

from concurrencytest import ConcurrentTestSuite, fork_for_tests
# pylint: disable=import-error
from mininet.log import setLogLevel
from mininet.clean import Cleanup
from packaging import version

import mininet_test_util

# Only these hardware types will be tested with meters.
SUPPORTS_METERS = (
    'Aruba',
    'NoviFlow',
    'Open vSwitch',
)


EXTERNAL_DEPENDENCIES = (
    ('ryu-manager', ['--version'],
     'ryu-manager', r'ryu-manager (\d+\.\d+)\n', "4.9"),
    ('ovs-vsctl', ['--version'], 'Open vSwitch',
     r'ovs-vsctl\s+\(Open vSwitch\)\s+(\d+\.\d+)\.\d+\n', "2.3"),
    ('tcpdump', ['-h'], 'tcpdump',
     r'tcpdump\s+version\s+(\d+\.\d+)\.\d+\n', "4.5"),
    ('nc', ['-h'], 'OpenBSD netcat', '', 0),
    ('vconfig', [], 'the VLAN you are talking about', '', 0),
    ('2to3', ['--help'], 'Usage: 2to3', '', 0),
    ('fuser', ['-V'], r'fuser \(PSmisc\)',
     r'fuser \(PSmisc\) (\d+\.\d+)\n', "22.0"),
    ('lsof', ['-v'], r'lsof version',
     r'revision: (\d+\.\d+)\n', "4.86"),
    ('mn', ['--version'], r'\d+\.\d+.\d+',
     r'(\d+\.\d+).\d+', "2.2"),
    ('exabgp', ['--version'], 'ExaBGP',
     r'ExaBGP : (\d+\.\d+).\d+', "4.0"),
    ('pip', ['show', 'influxdb'], 'influxdb',
     r'Version:\s+(\d+\.\d+)\.\d+', "3.0"),
    ('pylint', ['--version'], 'pylint',
     r'pylint (\d+\.\d+).\d+,', "1.6"),
    ('curl', ['--version'], 'libcurl',
     r'curl (\d+\.\d+).\d+', "7.3"),
    ('ladvd', ['-h'], 'ladvd',
     r'ladvd version (\d+\.\d+)\.\d+', "0.9"),
    ('iperf', ['--version'], 'iperf',
     r'iperf version (\d+\.\d+)\.\d+', "2.0"),
    ('fping', ['-v'], 'fping',
     r'fping: Version (\d+\.\d+)', "3.10"),
    ('rdisc6', ['-V'], 'ndisc6',
     r'ndisc6.+tool (\d+\.\d+)', "1.0"),
    ('tshark', ['-v'], 'tshark',
     r'TShark.+(\d+\.\d+)', "2.1"),
    ('scapy', ['-h'], 'Usage: scapy', '', 0),
)

# Must pass with 0 lint errors
FAUCET_LINT_SRCS = glob.glob(
    os.path.join(mininet_test_util.FAUCET_DIR, '*py'))
FAUCET_TEST_LINT_SRCS = glob.glob(
    os.path.join(os.path.dirname(__file__), 'mininet_test*py'))

# see hw_switch_config.yaml for how to bridge in an external hardware switch.
HW_SWITCH_CONFIG_FILE = 'hw_switch_config.yaml'
CONFIG_FILE_DIRS = ['/etc/faucet', './', '/faucet-src']
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
                binary_args,
                stdin=mininet_test_util.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                close_fds=True)
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
            print('%s not present or did not return expected string %s (%s)' % (
                required_binary, binary_present_re, binary_output))
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
    for faucet_src in FAUCET_LINT_SRCS: # + FAUCET_TEST_LINT_SRCS:
        ret = subprocess.call(
            ['env',
             'PYTHONPATH=%s' % mininet_test_util.FAUCET_DIR,
             'pylint',
             '--rcfile=/dev/null',
             '-E', faucet_src],
            stdin=mininet_test_util.DEVNULL,
            close_fds=True)
        if ret:
            print(('pylint of %s returns an error' % faucet_src))
            return False
    for faucet_src in FAUCET_LINT_SRCS:
        output_2to3 = subprocess.check_output(
            ['2to3', '--nofix=import', faucet_src],
            stdin=mininet_test_util.DEVNULL,
            stderr=mininet_test_util.DEVNULL,
            close_fds=True)
        if output_2to3:
            print(('2to3 of %s returns a diff (not python3 compatible)' % faucet_src))
            print(output_2to3)
            return False
    return True


def make_suite(tc_class, hw_config, root_tmpdir, ports_sock, max_test_load):
    """Compose test suite based on test class names."""
    testloader = unittest.TestLoader()
    testnames = testloader.getTestCaseNames(tc_class)
    suite = unittest.TestSuite()
    for name in testnames:
        suite.addTest(tc_class(name, hw_config, root_tmpdir, ports_sock, max_test_load))
    return suite


def pipeline_superset_report(decoded_pcap_logs):
    """Report on matches, instructions, and actions by table from tshark logs."""

    def parse_flow(flow_lines):
        table_id = None
        group_id = None
        last_oxm_match = ''
        matches_count = 0
        actions_count = 0
        instructions_count = 0

        for flow_line, depth, section_stack in flow_lines:
            if depth == 1:
                if flow_line.startswith('Type: OFPT_'):
                    if not (flow_line.startswith('Type: OFPT_FLOW_MOD') or
                            flow_line.startswith('Type: OFPT_GROUP_MOD')):
                        return
                if flow_line.startswith('Table ID'):
                    if not flow_line.startswith('Table ID: OFPTT_ALL'):
                        table_id = int(flow_line.split()[-1])
                    else:
                        return
                if flow_line.startswith('Group ID'):
                    if not flow_line.startswith('Group ID: OFPG_ALL'):
                        group_id = int(flow_line.split()[-1])
                    else:
                        return
                continue
            elif depth > 1:
                section_name = section_stack[-1]
                if table_id is not None:
                    if 'Match' in section_stack:
                        if section_name == 'OXM field':
                            oxm_match = re.match(r'.*Field: (\S+).*', flow_line)
                            if oxm_match:
                                table_matches[table_id].add(oxm_match.group(1))
                                last_oxm_match = oxm_match.group(1)
                                matches_count += 1
                                if matches_count > table_matches_max[table_id]:
                                    table_matches_max[table_id] = matches_count
                            else:
                                oxm_mask_match = re.match(r'.*Has mask: True.*', flow_line)
                                if oxm_mask_match:
                                    table_matches[table_id].add(last_oxm_match + '/Mask')
                    elif 'Instruction' in section_stack:
                        type_match = re.match(r'Type: (\S+).+', flow_line)
                        if type_match:
                            if section_name == 'Instruction':
                                table_instructions[table_id].add(type_match.group(1))
                                instructions_count += 1
                                if instructions_count > table_instructions_max[table_id]:
                                    table_instructions_max[table_id] = instructions_count
                            elif section_name == 'Action':
                                table_actions[table_id].add(type_match.group(1))
                                actions_count += 1
                                if actions_count > table_actions_max[table_id]:
                                    table_actions_max[table_id] = actions_count
                elif group_id is not None:
                    if 'Bucket' in section_stack:
                        type_match = re.match(r'Type: (\S+).+', flow_line)
                        if type_match:
                            if section_name == 'Action':
                                group_actions.add(type_match.group(1))

    group_actions = set()
    table_matches = collections.defaultdict(set)
    table_matches_max = collections.defaultdict(lambda: 0)
    table_instructions = collections.defaultdict(set)
    table_instructions_max = collections.defaultdict(lambda: 0)
    table_actions = collections.defaultdict(set)
    table_actions_max = collections.defaultdict(lambda: 0)

    for log in decoded_pcap_logs:
        packets = re.compile(r'\n{2,}').split(open(log).read())
        for packet in packets:
            last_packet_line = None
            indent_count = 0
            last_indent_count = 0
            section_stack = []
            flow_lines = []

            for packet_line in packet.splitlines():
                orig_packet_line = len(packet_line)
                packet_line = packet_line.lstrip()
                indent_count = orig_packet_line - len(packet_line)
                if indent_count == 0:
                    parse_flow(flow_lines)
                    flow_lines = []
                    section_stack = []
                elif indent_count > last_indent_count:
                    section_stack.append(last_packet_line)
                elif indent_count < last_indent_count:
                    if section_stack:
                        section_stack.pop()
                depth = len(section_stack)
                last_indent_count = indent_count
                last_packet_line = packet_line
                flow_lines.append((packet_line, depth, copy.copy(section_stack)))
            parse_flow(flow_lines)


    for table in sorted(table_matches):
        print('table: %u' % table)
        print('  matches: %s (max %u)' % (
            sorted(table_matches[table]), table_matches_max[table]))
        print('  table_instructions: %s (max %u)' % (
            sorted(table_instructions[table]), table_instructions_max[table]))
        print('  table_actions: %s (max %u)' % (
            sorted(table_actions[table]), table_actions_max[table]))
    if group_actions:
        print('group bucket actions:')
        print('  %s' % sorted(group_actions))


def filter_test_hardware(test_obj, hw_config):
    test_links = (test_obj.N_TAGGED + test_obj.N_UNTAGGED) * test_obj.LINKS_PER_HOST
    if hw_config is not None:
        test_hardware = hw_config['hardware']
        if test_obj.NUM_DPS != 1:
            return False
        if test_links < REQUIRED_TEST_PORTS:
            if test_hardware == 'ZodiacFX':
                return True
            return False
        if test_obj.REQUIRES_METERS:
            if test_hardware not in SUPPORTS_METERS:
                return False
    else:
        if test_obj.NUM_DPS == 1 and test_links < REQUIRED_TEST_PORTS:
            return False
    return True


def max_loadavg():
    return multiprocessing.cpu_count()


def expand_tests(module, requested_test_classes, excluded_test_classes,
                 hw_config, root_tmpdir, ports_sock, serial):
    sanity_test_suites = []
    single_test_suites = []
    parallel_test_suites = []

    for full_name, test_obj in inspect.getmembers(sys.modules[module]):
        test_name = full_name.split('.')[-1]
        if not inspect.isclass(test_obj):
            continue
        if requested_test_classes and test_name not in requested_test_classes:
            continue
        if excluded_test_classes and test_name in excluded_test_classes:
            continue
        if test_name.endswith('Test') and test_name.startswith('Faucet'):
            if not filter_test_hardware(test_obj, hw_config):
                continue
            print('adding test %s' % test_name)
            test_suite = make_suite(
                test_obj, hw_config, root_tmpdir, ports_sock, max_loadavg())
            if test_name.startswith('FaucetSanity'):
                sanity_test_suites.append(test_suite)
            else:
                if serial or test_name.startswith('FaucetSingle'):
                    single_test_suites.append(test_suite)
                else:
                    parallel_test_suites.append(test_suite)

    sanity_tests = unittest.TestSuite()
    single_tests = unittest.TestSuite()
    parallel_tests = unittest.TestSuite()

    if len(parallel_test_suites) == 1:
        single_test_suites.extend(parallel_test_suites)
        parallel_test_suites = []
    if len(parallel_test_suites) > 0:
        seed = time.time()
        print('seeding parallel test shuffle with %f' % seed)
        random.seed(seed)
        random.shuffle(parallel_test_suites)
        for test_suite in parallel_test_suites:
            parallel_tests.addTest(test_suite)

    for test_suite in sanity_test_suites:
        sanity_tests.addTest(test_suite)
    for test_suite in single_test_suites:
        single_tests.addTest(test_suite)
    return (sanity_tests, single_tests, parallel_tests)


class CleanupResult(unittest.runner.TextTestResult):

    root_tmpdir = None
    successes = []

    def addSuccess(self, test):
        self.successes.append((test, ''))
        test_tmpdir = os.path.join(
            self.root_tmpdir, mininet_test_util.flat_test_name(test.id()))
        shutil.rmtree(test_tmpdir)
        super(CleanupResult, self).addSuccess(test)


def test_runner(root_tmpdir, resultclass, failfast=False):
    resultclass.root_tmpdir = root_tmpdir
    return unittest.TextTestRunner(verbosity=255, resultclass=resultclass, failfast=failfast)


def run_parallel_test_suites(root_tmpdir, resultclass, parallel_tests):
    results = []
    if parallel_tests.countTestCases():
        max_parallel_tests = min(parallel_tests.countTestCases(), max_loadavg() * 2)
        print('running maximum of %u parallel tests' % max_parallel_tests)
        parallel_runner = test_runner(root_tmpdir, resultclass)
        parallel_suite = ConcurrentTestSuite(
            parallel_tests, fork_for_tests(max_parallel_tests))
        results.append(parallel_runner.run(parallel_suite))
    return results


def run_single_test_suites(root_tmpdir, resultclass, single_tests):
    results = []
    # TODO: Tests that are serialized generally depend on hardcoded ports.
    # Make them use dynamic ports.
    if single_tests.countTestCases():
        single_runner = test_runner(root_tmpdir, resultclass)
        results.append(single_runner.run(single_tests))
    return results


def run_sanity_test_suite(root_tmpdir, resultclass, sanity_tests):
    sanity_runner = test_runner(root_tmpdir, resultclass, failfast=True)
    sanity_result = sanity_runner.run(sanity_tests)
    return sanity_result.wasSuccessful()


def report_tests(test_status, test_list):
    for test_class, test_text in test_list:
        test_text = test_text.replace('\n', '\t')
        print('\t'.join((test_class.id(), test_status, test_text)))


def report_results(results):
    if results:
        report_title = 'test results'
        print('\n')
        print(report_title)
        print('=' * len(report_title))
        print('\n')
        for result in results:
            test_lists = [
                ('ERROR', result.errors),
                ('FAIL', result.failures),
            ]
            if hasattr(result, 'successes'):
                test_lists.append(
                    ('OK', result.successes))
            for test_status, test_list in test_lists:
                report_tests(test_status, test_list)
        print('\n')


def run_test_suites(root_tmpdir, resultclass, single_tests, parallel_tests):
    print('running %u tests in parallel and %u tests serial' % (
        parallel_tests.countTestCases(), single_tests.countTestCases()))
    results = []
    results.extend(run_parallel_test_suites(root_tmpdir, resultclass, parallel_tests))
    results.extend(run_single_test_suites(root_tmpdir, resultclass, single_tests))
    report_results(results)
    successful_results = [result for result in results if result.wasSuccessful()]
    return len(results) == len(successful_results)


def start_port_server(root_tmpdir, start_free_ports, min_free_ports):
    ports_sock = os.path.join(root_tmpdir, '.ports-server')
    ports_server = threading.Thread(
        target=mininet_test_util.serve_ports,
        args=(ports_sock, start_free_ports, min_free_ports))
    ports_server.setDaemon(True)
    ports_server.start()
    for _ in range(min_free_ports / 2):
        if os.path.exists(ports_sock):
            break
        time.sleep(1)
    if not os.path.exists(ports_sock):
        print('ports server did not start (%s not created)' % ports_sock)
        sys.exit(-1)
    return ports_sock


def dump_failed_test_file(test_file, only_exts):
    dump_file = False
    test_file_content = open(test_file).read()
    if test_file_content:
        if only_exts:
            for ext in only_exts:
                if test_file.endswith(ext):
                    dump_file = True
                    break
        else:
            dump_file = True

    if dump_file:
        print(test_file)
        print('=' * len(test_file))
        print('\n')
        print(test_file_content)
    return dump_file


def dump_failed_test(test_name, test_dir):
    print(test_name)
    print('=' * len(test_name))
    print('\n')
    test_files = set(glob.glob(os.path.join(test_dir, '*')))
    dumped_test_files = set()

    for only_exts in (['.yaml'], ['.log'], ['.cap.txt'], ['.txt']):
        for test_file in sorted(test_files):
            if test_file in dumped_test_files:
                continue
            if dump_failed_test_file(test_file, only_exts):
                dumped_test_files.add(test_file)


def clean_test_dirs(root_tmpdir, all_successful, sanity, keep_logs, dumpfail):
    if all_successful:
        if not keep_logs:
            shutil.rmtree(root_tmpdir)
    else:
        print('\nlog/debug files for failed tests are in %s\n' % root_tmpdir)
        if not keep_logs:
            if sanity:
                test_dirs = glob.glob(os.path.join(root_tmpdir, '*'))
                for test_dir in test_dirs:
                    test_name = os.path.basename(test_dir)
                    if dumpfail:
                        dump_failed_test(test_name, test_dir)


def run_tests(module, hw_config, requested_test_classes, dumpfail,
              keep_logs, serial, excluded_test_classes):
    """Actually run the test suites, potentially in parallel."""
    if hw_config is not None:
        print('Testing hardware, forcing test serialization')
        serial = True
    root_tmpdir = tempfile.mkdtemp(prefix='faucet-tests-', dir='/var/tmp')
    print('Logging test results in %s' % root_tmpdir)
    start_free_ports = 10
    min_free_ports = 200
    ports_sock = start_port_server(root_tmpdir, start_free_ports, min_free_ports)
    print('test ports server started')
    sanity_tests, single_tests, parallel_tests = expand_tests(
        module, requested_test_classes, excluded_test_classes,
        hw_config, root_tmpdir, ports_sock, serial)
    resultclass = CleanupResult
    if keep_logs:
        resultclass = resultclass.__bases__[0]
    all_successful = False
    sanity = run_sanity_test_suite(root_tmpdir, resultclass, sanity_tests)
    if sanity:
        all_successful = run_test_suites(
            root_tmpdir, resultclass, single_tests, parallel_tests)
    os.remove(ports_sock)
    decoded_pcap_logs = glob.glob(os.path.join(
        os.path.join(root_tmpdir, '*'), '*of.cap.txt'))
    pipeline_superset_report(decoded_pcap_logs)
    clean_test_dirs(root_tmpdir, all_successful, sanity, keep_logs, dumpfail)
    if not all_successful:
        sys.exit(-1)


def parse_args():
    """Parse command line arguments."""
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            'cdknsix:',
            ['clean', 'dumpfail', 'keep_logs', 'nocheck', 'serial', 'integration'])
    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    clean = False
    dumpfail = False
    keep_logs = False
    nocheck = False
    serial = False
    excluded_test_classes = []
    integration = True # By definition these are all integration tests.

    for opt, arg in opts:
        if opt in ('-c', '--clean'):
            clean = True
        if opt in ('-d', '--dumpfail'):
            dumpfail = True
        if opt in ('-k', '--keep_logs'):
            keep_logs = True
        if opt in ('-n', '--nocheck'):
            nocheck = True
        if opt in ('-i', '--integration'):
            integration = True
        if opt in ('-s', '--serial'):
            serial = True
        if opt == '-x':
            excluded_test_classes.append(arg)

    return (
        args, clean, dumpfail, keep_logs, nocheck,
        serial, excluded_test_classes)


def test_main(module):
    """Test main."""
    setLogLevel('error')
    print('testing module %s' % module)
    (requested_test_classes, clean, dumpfail, keep_logs, nocheck,
     serial, excluded_test_classes) = parse_args()

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
    run_tests(
        module, hw_config, requested_test_classes, dumpfail,
        keep_logs, serial, excluded_test_classes)
