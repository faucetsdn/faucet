#!/usr/bin/python

"""Standalone utility functions for Mininet tests."""


def str_int_dpid(hex_dpid):
    """Return stringed-int DPID, from a stringed-hex DPID."""
    return str(int(hex_dpid, 16))
