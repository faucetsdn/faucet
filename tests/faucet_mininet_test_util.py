#!/usr/bin/python

"""Standalone utility functions for Mininet tests."""

import socket

RESERVED_FOR_TESTS_PORTS = (5001, 5002)


def str_int_dpid(hex_dpid):
    """Return stringed-int DPID, from a stringed-hex DPID."""
    return str(int(hex_dpid, 16))


def find_free_port():
    """Return a free TCP port."""
    while True:
        free_socket = socket.socket()
        free_socket.bind(('', 0))
        free_port = free_socket.getsockname()[1]
        free_socket.close()
        if free_port not in RESERVED_FOR_TESTS_PORTS:
            break
    return free_port

