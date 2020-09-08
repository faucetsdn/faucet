#!/usr/bin/env python3

"""Mininet test runner

 * must be run as root
 * you can run a specific test case only, by adding the class name of the test
   case to the command. Eg ./mininet_test.py FaucetUntaggedIPv4RouteTest

It is strongly recommended to run these tests via Docker, to ensure you have
all dependencies correctly installed. See ../docs/.
"""

# pylint: disable=missing-docstring

import argparse
import collections
import copy
import cProfile
import json
import glob
import inspect
import os
import sys
import multiprocessing
import pstats
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

import yaml

from packaging import version

from concurrencytest import ConcurrentTestSuite, fork_for_tests
from mininet.log import setLogLevel
from mininet.clean import Cleanup

from clib import mininet_test_util

DEFAULT_HARDWARE = 'Open vSwitch'

# Only these hardware types will be tested with meters.
SUPPORTS_METERS = (
    DEFAULT_HARDWARE,  # TODO: tested with OVS userspace only.
    'Aruba',
    'NoviFlow',
    'ZodiacGX',
)

SUPPORTS_METADATA = (
    DEFAULT_HARDWARE,
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
    ('fuser', ['-V'], r'fuser \(PSmisc\)',
     r'fuser \(PSmisc\) (\d+\.\d+)\n', "22.0"),
    ('lsof', ['-v'], r'lsof version',
     r'revision: (\d+\.\d+)\n', "4.86"),
    ('mn', ['--version'], r'\d+\.\d+.\d+',
     r'(\d+\.\d+).\d+', "2.2"),
    ('exabgp', ['--version'], 'ExaBGP',
     r'ExaBGP : (\d+\.\d+).\d+', "4.0"),
    ('pip3', ['show', 'influxdb'], 'influxdb',
     r'Version:\s+(\d+\.\d+)\.\d+', "3.0"),
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
    ('tshark', ['-v'], r'(?i)tshark',
     r'TShark\s*[a-zA-Z\(\)]*\s*([\d\.]+)', "2.1"),
    ('scapy', ['-h'], 'Usage: scapy', '', 0),
)

# see hw_switch_config.yaml for how to bridge in an external hardware switch.
HW_SWITCH_CONFIG_FILE = 'hw_switch_config.yaml'
CONFIG_FILE_DIRS = ['/etc/faucet', './', '/faucet-src']
REQUIRED_TEST_PORTS = 4

REQUIRED_HW_CONFIG = {
    'dp_ports': (dict,),
    'cpn_intf': (str,),
    'dpid': (int,),
    'hardware': (str,),
    'hw_switch': (bool,),
    'of_port': (int,),
    'gauge_of_port': (int,),
}

OPTIONAL_HW_CONFIG = {
    'cpn_ipv6': (bool,),
    'ctl_privkey': (str,),
    'ca_certs': (str,),
    'ctl_cert': (str,),
}

ALL_HW_CONFIG = {**REQUIRED_HW_CONFIG, **OPTIONAL_HW_CONFIG}


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
            config = yaml.safe_load(config_file)
    except IOError:
        print('Could not load YAML config data from %s' % config_file_name)
        sys.exit(-1)
    if config.get('hw_switch', False):
        unknown_keys = set(config.keys()) - set(ALL_HW_CONFIG.keys())
        if unknown_keys:
            print('unknown config %s in %s' % (unknown_keys, config_file_name))
            sys.exit(-1)
        missing_required_keys = set(REQUIRED_HW_CONFIG.keys()) - set(config.keys())
        if missing_required_keys:
            print('missing required config: %s' % missing_required_keys)
            sys.exit(-1)
        for config_key, config_value in config.items():
            valid_types = ALL_HW_CONFIG[config_key]
            valid_values = [
                config_value for valid_type in valid_types
                if isinstance(config_value, valid_type)]
            if not valid_values:
                print('%s (%s) must be of type %s in %s' % (
                    config_key, config_value,
                    valid_types, config_file_name))
                sys.exit(-1)
        dp_ports = config['dp_ports']
        if len(dp_ports) < REQUIRED_TEST_PORTS:
            print('At least %u dataplane ports are required, '
                  '%d are provided in %s.' %
                  (REQUIRED_TEST_PORTS, len(dp_ports), config_file_name))
            sys.exit(-1)
        return config
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
            binary_output = proc_out.decode()
            if proc_err is not None:
                binary_output += proc_err.decode()
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


def make_suite(tc_class, hw_config, root_tmpdir, ports_sock, max_test_load,
               port_order, start_port):
    """Compose test suite based on test class names."""
    testloader = unittest.TestLoader()
    testnames = testloader.getTestCaseNames(tc_class)
    suite = unittest.TestSuite()
    for name in testnames:
        suite.addTest(tc_class(
            name, hw_config, root_tmpdir, ports_sock, max_test_load,
            port_order, start_port))
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
        oxm_match_re = re.compile(r'.*Field: (\S+).*')
        oxm_mask_match_re = re.compile(r'.*Has mask: True.*')
        type_match_re = re.compile(r'Type: (\S+).+')

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
                            oxm_match = oxm_match_re.match(flow_line)
                            if oxm_match:
                                table_matches[table_id].add(oxm_match.group(1))
                                last_oxm_match = oxm_match.group(1)
                                matches_count += 1
                                if matches_count > table_matches_max[table_id]:
                                    table_matches_max[table_id] = matches_count
                            else:
                                oxm_mask_match = oxm_mask_match_re.match(flow_line)
                                if oxm_mask_match:
                                    table_matches[table_id].add(last_oxm_match + '/Mask')
                    elif 'Instruction' in section_stack:
                        type_match = type_match_re.match(flow_line)
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
                        type_match = type_match_re.match(flow_line)
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
    test_hosts = test_obj.N_TAGGED + test_obj.N_UNTAGGED + test_obj.N_EXTENDED
    test_links = test_hosts * test_obj.LINKS_PER_HOST
    testing_hardware = hw_config is not None
    test_hardware = DEFAULT_HARDWARE
    if testing_hardware:
        test_hardware = hw_config['hardware']

    if test_obj.REQUIRES_METERS and test_hardware not in SUPPORTS_METERS:
        return False

    if test_obj.REQUIRES_METADATA and test_hardware not in SUPPORTS_METADATA:
        return False

    if testing_hardware:
        if test_obj.SOFTWARE_ONLY:
            return False
        if test_obj.NUM_DPS > 1:
            # TODO: test other stacking combinations.
            if test_obj.NUM_HOSTS > 2:
                return False

    if test_obj.NUM_DPS == 1 and test_links < REQUIRED_TEST_PORTS:
        return False

    return True


def max_loadavg():
    return int(multiprocessing.cpu_count() * 1.5)


def expand_tests(modules, requested_test_classes, regex_test_classes, excluded_test_classes,
                 hw_config, root_tmpdir, ports_sock, serial,
                 port_order, start_port):
    sanity_test_suites = []
    single_test_suites = []
    parallel_test_suites = []

    for module in modules:
        for full_name, test_obj in inspect.getmembers(sys.modules[module]):
            test_name = full_name.split('.')[-1]
            if not inspect.isclass(test_obj):
                continue
            if regex_test_classes or requested_test_classes:
                if not ((regex_test_classes and regex_test_classes.match(test_name)) or (
                        requested_test_classes and test_name in requested_test_classes)):
                    continue
            if excluded_test_classes and test_name in excluded_test_classes:
                continue
            if test_name.endswith('Test') and test_name.startswith('Faucet'):
                if not filter_test_hardware(test_obj, hw_config):
                    continue
                print('adding test %s' % test_name)
                test_suite = make_suite(
                    test_obj, hw_config, root_tmpdir, ports_sock, max_loadavg(),
                    port_order, start_port)
                if test_name.startswith('FaucetSanity'):
                    sanity_test_suites.append(test_suite)
                else:
                    if serial or test_name.startswith('FaucetSingle') or test_obj.NETNS:
                        single_test_suites.append(test_suite)
                    else:
                        parallel_test_suites.append(test_suite)

        sanity_tests = unittest.TestSuite()
        single_tests = unittest.TestSuite()
        parallel_tests = unittest.TestSuite()

        if len(parallel_test_suites) == 1:
            single_test_suites.extend(parallel_test_suites)
            parallel_test_suites = []
        if parallel_test_suites:
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


class FaucetResult(unittest.runner.TextTestResult): # pytype: disable=module-attr

    root_tmpdir = None
    test_duration_secs = {}

    def _test_tmpdir(self, test):
        return os.path.join(
            self.root_tmpdir, mininet_test_util.flat_test_name(test.id()))

    def _set_test_duration_secs(self, test):
        duration_file_name = os.path.join(self._test_tmpdir(test), 'test_duration_secs')
        if test.id() not in self.test_duration_secs:
            self.test_duration_secs[test.id()] = 0
        try:
            with open(duration_file_name) as duration_file:
                self.test_duration_secs[test.id()] = int(duration_file.read())
        except FileNotFoundError:
            pass

    def stopTest(self, test):
        self._set_test_duration_secs(test)
        super(FaucetResult, self).stopTest(test)


class FaucetCleanupResult(FaucetResult):

    successes = []

    def addSuccess(self, test):
        self._set_test_duration_secs(test)
        shutil.rmtree(self._test_tmpdir(test))
        self.successes.append((test, ''))
        super(FaucetCleanupResult, self).addSuccess(test)


def debug_exception_handler(etype, value, trace):
    import traceback
    import pdb
    traceback.print_exception(etype, value, trace)
    print()
    pdb.pm()


def test_runner(root_tmpdir, resultclass, failfast=False):
    resultclass.root_tmpdir = root_tmpdir
    return unittest.TextTestRunner(verbosity=255, resultclass=resultclass, failfast=failfast)


def run_parallel_test_suites(root_tmpdir, resultclass, parallel_tests):
    results = []
    if parallel_tests.countTestCases():
        max_parallel_tests = min(parallel_tests.countTestCases(), max_loadavg())
        print('running maximum of %u parallel tests' % max_parallel_tests)
        parallel_runner = test_runner(root_tmpdir, resultclass)
        parallel_suite = ConcurrentTestSuite(
            parallel_tests, fork_for_tests(max_parallel_tests))
        results.append(parallel_runner.run(parallel_suite))
    return results


def run_single_test_suites(debug, root_tmpdir, resultclass, single_tests):
    results = []
    # TODO: Tests that are serialized generally depend on hardcoded ports.
    # Make them use dynamic ports.
    if single_tests.countTestCases():
        single_runner = test_runner(root_tmpdir, resultclass)
        if debug:
            oldexcepthook = sys.excepthook
            sys.excepthook = debug_exception_handler
            single_tests.debug()
            sys.excepthook = oldexcepthook
        else:
            results.append(single_runner.run(single_tests))
    return results


def run_sanity_test_suite(root_tmpdir, resultclass, sanity_tests):
    sanity_runner = test_runner(root_tmpdir, resultclass, failfast=True)
    sanity_result = sanity_runner.run(sanity_tests)
    return sanity_result


def report_tests(test_status, test_list, result):
    tests_json = {}
    for test_class, test_text in test_list:
        test_text = test_text.replace('\n', '\t')
        test_text = test_text.replace('"', '\'')
        test_duration_secs = result.test_duration_secs[test_class.id()]
        tests_json.update({
            test_class.id(): {
                'status': test_status,
                'output': test_text,
                'test_duration_secs': test_duration_secs
                }})
    return tests_json


def report_results(results, hw_config, report_json_filename):
    if results:
        tests_json = {}
        report_title = 'test results'
        print('\n')
        print(report_title)
        print('=' * len(report_title))
        for result in results:
            test_lists = [
                ('ERROR', result.errors),
                ('FAIL', result.failures),
                ('SKIPPED', result.skipped),
            ]
            if hasattr(result, 'successes'):
                test_lists.append(
                    ('OK', result.successes))
            for test_status, test_list in test_lists:
                tests_json.update(report_tests(test_status, test_list, result))
        print(yaml.dump(
            tests_json, default_flow_style=False, explicit_start=True, explicit_end=True))
        if report_json_filename:
            report_json = {
                'hw_config': hw_config,
                'tests': tests_json,
            }
            with open(report_json_filename, 'w') as report_json_file:
                report_json_file.write(json.dumps(report_json))


def run_test_suites(debug, report_json_filename, hw_config, root_tmpdir,
                    resultclass, single_tests, parallel_tests, sanity_result):
    print('running %u tests in parallel and %u tests serial' % (
        parallel_tests.countTestCases(), single_tests.countTestCases()))
    results = []
    results.append(sanity_result)
    results.extend(run_parallel_test_suites(root_tmpdir, resultclass, parallel_tests))
    results.extend(run_single_test_suites(debug, root_tmpdir, resultclass, single_tests))
    report_results(results, hw_config, report_json_filename)
    successful_results = [result for result in results if result.wasSuccessful()]
    return len(results) == len(successful_results)


def start_port_server(root_tmpdir, start_free_ports, min_free_ports):
    ports_sock = os.path.join(root_tmpdir, '.ports-server')
    ports_server = threading.Thread(
        target=mininet_test_util.serve_ports,
        args=(ports_sock, start_free_ports, min_free_ports))
    ports_server.setDaemon(True)
    ports_server.start()
    for _ in range(min_free_ports // 2):
        if os.path.exists(ports_sock):
            break
        time.sleep(1)
    if not os.path.exists(ports_sock):
        print('ports server did not start (%s not created)' % ports_sock)
        sys.exit(-1)
    return ports_sock


def dump_failed_test_file(test_file, only_exts):
    dump_file = False
    if only_exts:
        for ext in only_exts:
            if test_file.endswith(ext):
                dump_file = True
                break
    else:
        dump_file = True

    if dump_file:
        try:
            test_file_content = open(test_file).read()
            if test_file_content:
                print(test_file)
                print('=' * len(test_file))
                print('\n')
                print(test_file_content)
        except UnicodeDecodeError:
            pass
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
        if not keep_logs or not os.listdir(root_tmpdir):
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


def run_tests(modules, hw_config, requested_test_classes, regex_test_classes, dumpfail, debug,
              keep_logs, serial, repeat, excluded_test_classes, report_json_filename,
              port_order, start_port):
    """Actually run the test suites, potentially in parallel."""
    if repeat:
        print('Will repeat tests until failure')
    if hw_config is not None:
        print('Testing hardware, forcing test serialization')
        serial = True
    root_tmpdir = tempfile.mkdtemp(prefix='faucet-tests-', dir='/var/tmp')
    print('Logging test results in %s' % root_tmpdir)
    start_free_ports = 10
    min_free_ports = 200
    if serial:
        start_free_ports = 5
        min_free_ports = 5
    ports_sock = start_port_server(root_tmpdir, start_free_ports, min_free_ports)
    print('test ports server started')
    resultclass = FaucetCleanupResult
    if keep_logs:
        resultclass = FaucetResult
    all_successful = False
    no_tests = True

    sanity_tests, single_tests, parallel_tests = expand_tests(
        modules, requested_test_classes, regex_test_classes, excluded_test_classes,
        hw_config, root_tmpdir, ports_sock, serial, port_order, start_port)

    if sanity_tests.countTestCases() + single_tests.countTestCases() + parallel_tests.countTestCases():
        no_tests = False
        sanity_result = run_sanity_test_suite(root_tmpdir, resultclass, sanity_tests)
        if sanity_result.wasSuccessful():
            while True:
                all_successful = run_test_suites(
                    debug, report_json_filename,
                    hw_config, root_tmpdir, resultclass,
                    copy.deepcopy(single_tests),
                    copy.deepcopy(parallel_tests),
                    sanity_result)
                if not repeat:
                    break
                if not all_successful:
                    break
                print('repeating run')
        else:
            report_results([sanity_result], hw_config, report_json_filename)

    if no_tests:
        print('no tests selected')
        shutil.rmtree(root_tmpdir)
        sys.exit(0)
    else:
        decoded_pcap_logs = glob.glob(os.path.join(
            os.path.join(root_tmpdir, '*'), '*of.cap.txt'))
        pipeline_superset_report(decoded_pcap_logs)
        clean_test_dirs(
            root_tmpdir, all_successful,
            sanity_result.wasSuccessful(), keep_logs, dumpfail)

    if not all_successful:
        sys.exit(-1)


def parse_args():
    """Parse command line arguments."""

    parser = argparse.ArgumentParser(
        prog='mininet_tests')
    parser.add_argument(
        '--regex', help='run tests that match regular expression pattern')
    parser.add_argument(
        '-c', '--clean', action='store_true', help='run mininet cleanup')
    parser.add_argument(
        '-d', '--dumpfail', action='store_true', help='dump logs for failed tests')
    parser.add_argument(
        '--debug', action='store_true', help='enter debug breakpoint on assertion failure')
    parser.add_argument(
        '-i', '--integration', default=True, action='store_true', help='run integration tests')
    parser.add_argument(
        '-j', '--jsonreport', help='write a json file with test results')
    parser.add_argument(
        '-k', '--keep_logs', action='store_true', help='keep logs even for OK tests')
    loglevels = ('debug', 'error', 'warning', 'info', 'output')
    parser.add_argument(
        '-l', '--loglevel', choices=loglevels, default='warning',
        help='set mininet logging level')
    parser.add_argument(
        '-n', '--nocheck', action='store_true', help='skip dependency check')
    parser.add_argument(
        '-o', '--order', default='random',
        help='port order for tests: 0,1,2,3 | random (default: random)')
    parser.add_argument(
        '-p', '--profile', action='store_true',
        help='use Cprofile to report elapsed wall clock time per function')
    parser.add_argument(
        '--port', default='random',
        help='starting port number (integer) | random (default: random)')
    parser.add_argument(
        '-r', '--repeat', action='store_true', help='repeat tests until failure')
    parser.add_argument(
        '-s', '--serial', action='store_true', help='run tests serially')
    parser.add_argument(
        '--generative_unit', default=False, action='store_true', help='run generative unit tests')
    parser.add_argument(
        '--generative_integration', default=False, action='store_true',
        help='run generative integration tests')
    parser.add_argument(
        '-x', help='list of test classes to exclude')

    excluded_test_classes = []
    report_json_filename = None

    try:
        args, requested_test_classes = parser.parse_known_args(sys.argv[1:])
        if args.order == 'random':
            port_order = list(range(4))
            random.shuffle(port_order)
        else:
            port_order = [int(s) for s in args.order.split(',')]
        if sorted(port_order) != sorted(range(len(port_order))):
            print('Port order should be a permutation of 0,1,2,3')
            raise ValueError
        if args.port == 'random':
            start_port = random.randint(1, 10)
        else:
            start_port = int(args.port)
        regex_test_classes = None
        if args.regex:
            regex_test_classes = re.compile(args.regex)
            print('Running tests on classes matching %s' % args.regex)
    except(KeyError, IndexError, ValueError):
        parser.print_usage()
        sys.exit(-1)

    if args.jsonreport:
        report_json_filename = args.jsonreport
    if args.x:
        excluded_test_classes = args.x.split(',')

    return (
        requested_test_classes, regex_test_classes, args.clean, args.dumpfail, args.debug,
        args.keep_logs, args.nocheck, args.serial, args.repeat,
        excluded_test_classes, report_json_filename, port_order, start_port,
        args.loglevel, args.profile)


def test_main(modules):
    """Test main."""

    print('testing module %s' % modules)

    (requested_test_classes, regex_test_classes, clean, dumpfail, debug, keep_logs, nocheck,
     serial, repeat, excluded_test_classes, report_json_filename, port_order,
     start_port, loglevel, profile) = parse_args()

    setLogLevel(loglevel)

    if clean:
        print('Cleaning up test interfaces, processes and openvswitch '
              'configuration from previous test runs')
        Cleanup.cleanup()
        sys.exit(0)

    if nocheck:
        print('Skipping dependency checks')
    else:
        if not check_dependencies():
            print('dependency check failed. check required library/binary '
                  'list in header of this script')
            sys.exit(-1)

    print('port order: -o', ','.join(str(i) for i in port_order))
    print('start port: --port %s' % start_port)

    hw_config = import_hw_config()

    if profile:
        pr = cProfile.Profile(time.time)  # use wall clock time
        pr.enable()

    run_tests(
        modules, hw_config, requested_test_classes, regex_test_classes, dumpfail, debug,
        keep_logs, serial, repeat, excluded_test_classes, report_json_filename,
        port_order, start_port)

    if profile:
        pr.disable()
        ps = pstats.Stats(pr).sort_stats('cumulative')
        ps.print_stats()
