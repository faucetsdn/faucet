#!/usr/bin/env python3

"""Standalone utility functions for Mininet tests."""

import collections
import os
import socket
import subprocess
import time

# pylint: disable=import-error
from mininet.log import error, output


DEVNULL = open(os.devnull, 'wb', encoding=None)  # pylint: disable=consider-using-with
GETPORT = 'GETPORT'
PUTPORTS = 'PUTPORTS'
GETSERIAL = 'GETSERIAL'
LISTPORTS = 'LISTPORTS'
LOCALHOST = '127.0.0.1'
LOCALHOSTV6 = '::1'
FAUCET_DIR = os.getenv('FAUCET_DIR', '../faucet')
RESERVED_FOR_TESTS_PORTS = (179, 5001, 5002, 6633, 6653)
with open('/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait', encoding='utf-8') as pf:
    MIN_PORT_AGE = max(int(pf.read()) / 2, 10)


def flat_test_name(_id):
    """Return short form test name from TestCase ID."""
    return '-'.join(_id.split('.')[1:])


def lsof_tcp_listening_cmd(port, ipv, state, terse):
    """Return a command line for lsof for processes with specified TCP state."""
    terse_arg = ''
    if terse:
        terse_arg = '-t'
    return f'lsof -b -P -n {terse_arg} -sTCP:{state} -i {ipv} -a -i tcp:{port}'


def lsof_udp_listening_cmd(port, terse):
    """Return a command line for lsof for processes with specified TCP state."""
    terse_arg = ''
    if terse:
        terse_arg = '-t'
    return f'lsof -b -P -n {terse_arg} -i udp:{port} -a'


def tcp_listening_cmd(port, ipv=4, state='LISTEN', terse=True):
    """Call lsof_tcp_listening_cmd() with default args."""
    return lsof_tcp_listening_cmd(port, ipv, state, terse)


def udp_listening_cmd(port, terse=True):
    """Call lsof_tcp_listening_cmd() with default args."""
    return lsof_udp_listening_cmd(port, terse)


def mininet_dpid(int_dpid):
    """Return stringified hex version, of int DPID for mininet."""
    return str('%x' % int(int_dpid))


def str_int_dpid(str_dpid):
    """Return stringified int version, of int or hex DPID from YAML."""
    str_dpid = str(str_dpid)
    if str_dpid.startswith('0x'):
        return str(int(str_dpid, 16))
    return str(int(str_dpid))


def receive_sock_line(sock):
    """Receive a \n terminated line from a socket."""
    buf = ''
    while buf.find('\n') <= -1:
        buf += sock.recv(2**10).decode()
    return buf.strip()


def tcp_listening(port):
    """Return True if any process listening on a port."""
    return subprocess.call(
        tcp_listening_cmd(port).split(),
        stdin=DEVNULL,
        stdout=DEVNULL,
        stderr=DEVNULL,
        close_fds=True) == 0


def udp_listening(port):
    """Return True if any process listening on a port."""
    return subprocess.call(
        udp_listening_cmd(port).split(),
        stdin=DEVNULL,
        stdout=DEVNULL,
        stderr=DEVNULL,
        close_fds=True) == 0


def test_server_request(ports_socket, name, command):
    assert name is not None
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ports_socket)
    sock.sendall((f'{command},{name}\n').encode())
    output(f'{name} {command}\n')
    buf = receive_sock_line(sock)
    responses = [int(i) for i in buf.split('\n')]
    sock.close()
    if len(responses) == 1:
        responses = responses[0]
    output(f'{name} {command}: {responses}\n')
    return responses


def get_serialno(ports_socket, name):
    """Retrieve serial number from test server."""
    return test_server_request(ports_socket, name, GETSERIAL)


def find_free_port(ports_socket, name):
    """Retrieve a free TCP port from test server."""
    request_name = '-'.join((name, str(os.getpid())))
    while True:
        port = test_server_request(ports_socket, request_name, GETPORT)
        if not tcp_listening(port):
            return port
        error(f'port {port} is busy, try another')


def find_free_udp_port(ports_socket, name):
    request_name = '-'.join((name, str(os.getpid())))
    while True:
        port = test_server_request(ports_socket, request_name, GETPORT)
        if not udp_listening(port):
            return port
        error(f'port {port} is busy, try another')


def return_free_ports(ports_socket, name):
    """Notify test server that all ports under name are released."""
    return test_server_request(ports_socket, name, PUTPORTS)


def serve_ports(ports_socket, start_free_ports, min_free_ports):
    """Implement a TCP server to dispense free TCP ports."""
    ports_q = collections.deque()
    free_ports = set()
    port_age = {}
    serialno = 0

    def get_port():
        while True:
            free_socket = socket.socket()
            free_socket.bind(('', 0))
            free_port = free_socket.getsockname()[1]
            free_socket.close()
            if free_port < 1024:
                continue
            if free_port in RESERVED_FOR_TESTS_PORTS:
                continue
            if free_port in free_ports:
                continue
            break
        free_ports.add(free_port)
        port_age[free_port] = time.time()
        return free_port

    def queue_free_ports(min_queue_size):
        while len(ports_q) < min_queue_size:
            port = get_port()
            ports_q.append(port)
            port_age[port] = time.time()

    queue_free_ports(start_free_ports)
    ports_by_name = collections.defaultdict(set)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(ports_socket)
    sock.listen(1)
    cold_start = True

    while True:
        connection, _ = sock.accept()
        command, name = receive_sock_line(connection).split(',')
        response = None
        if command == GETSERIAL:
            serialno += 1
            response = serialno
        elif command == PUTPORTS:
            ports_returned = 0
            for port in ports_by_name[name]:
                ports_returned += 1
                ports_q.append(port)
                port_age[port] = time.time()
            del ports_by_name[name]
            response = ports_returned
            if ports_returned:
                cold_start = False
        elif command == GETPORT:
            while True:
                port = ports_q.popleft()
                if time.time() - port_age[port] > MIN_PORT_AGE or cold_start:
                    break
                ports_q.append(port)
                time.sleep(1)
            ports_by_name[name].add(port)
            response = port
            queue_free_ports(min_free_ports)
        elif command == LISTPORTS:
            response = list(ports_by_name[name])
        if response is not None:
            response_str = ''
            if isinstance(response, int):
                response = [response]
            response_str = ''.join(['%u\n' % i for i in response])
            connection.sendall(response_str.encode())  # pylint: disable=no-member
        connection.close()


def timeout_cmd(cmd, timeout):
    """Return a command line prefaced with a timeout wrappers and stdout/err unbuffered."""
    return f'timeout -sKILL {timeout}s stdbuf -o0 -e0 {cmd}'


def timeout_soft_cmd(cmd, timeout):
    """Same as timeout_cmd buf using SIGTERM on timeout."""
    return f'timeout {timeout}s stdbuf -o0 -e0 {cmd}'
