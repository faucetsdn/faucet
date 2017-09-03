#!/usr/bin/env python

"""Standalone utility functions for Mininet tests."""

import collections
import os
import socket
import subprocess
import time


LOCALHOST = u'127.0.0.1'
FAUCET_DIR = os.getenv('FAUCET_DIR', '../faucet')
RESERVED_FOR_TESTS_PORTS = (179, 5001, 5002, 6633, 6653)
MIN_PORT_AGE = max(int(open(
    '/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_time_wait').read()) / 2, 30)


def tcp_listening_cmd(port, ipv=4, state='LISTEN'):
    return 'lsof -b -P -n -t -sTCP:%s -i %u -a -i tcp:%u' % (state, ipv, port)


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
    buf = ''
    while buf.find('\n') <= -1:
        buf = buf + sock.recv(1024)
    return buf.strip()


def tcp_listening(port):
    DEVNULL = open(os.devnull, 'w')
    return subprocess.call(
        tcp_listening_cmd(port).split(), stdout=DEVNULL, stderr=DEVNULL, close_fds=True) == 0


def find_free_port(ports_socket, name):
    """Retrieve a free TCP port from test server."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ports_socket)
    sock.sendall('GET,%s\n' % name)
    buf = receive_sock_line(sock)
    return [int(x) for x in buf.strip().split()]


def return_free_ports(ports_socket, name):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ports_socket)
    sock.sendall('PUT,%s\n' % name)


def serve_ports(ports_socket, start_free_ports, min_free_ports):
    """Implement a TCP server to dispense free TCP ports."""
    ports_q = collections.deque()
    free_ports = set()
    port_age = {}

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
            time.sleep(0.1)

    queue_free_ports(start_free_ports)
    ports_served = 0
    ports_by_name = collections.defaultdict(set)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(ports_socket)
    sock.listen(1)

    while True:
        if len(ports_q) < min_free_ports:
            queue_free_ports(len(ports_q) + 1)

        connection, _ = sock.accept()
        command, name = receive_sock_line(connection).split(',')
        if command == 'PUT':
            for port in ports_by_name[name]:
                ports_q.append(port)
                port_age[port] = time.time()
            del ports_by_name[name]
        else:
            while True:
                port = ports_q.popleft()
                if time.time() - port_age[port] > MIN_PORT_AGE:
                    break
                ports_q.append(port)
                time.sleep(1)
            ports_served += 1
            ports_by_name[name].add(port)
            # pylint: disable=no-member
            connection.sendall('%u %u\n' % (port, ports_served))
        connection.close()


def timeout_cmd(cmd, timeout):
    return 'timeout -sKILL %us stdbuf -o0 -e0 %s' % (timeout, cmd)


def timeout_soft_cmd(cmd, timeout):
    return 'timeout %us stdbuf -o0 -e0 %s' % (timeout, cmd)
