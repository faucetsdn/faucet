"""Topology components for FAUCET Mininet unit tests."""

from mininet.node import OVSSwitch


class FaucetSwitch(OVSSwitch):
    """Switch that will be used by all tests (kernel based OVS)."""

    def __init__(self, name, **params):
        OVSSwitch.__init__(
            self, name=name, datapath='kernel', **params)
