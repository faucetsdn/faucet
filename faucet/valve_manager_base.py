"""Valve Manager base class"""

# pylint: disable=R0201
# pylint: disable=W0613
class ValveManagerBase: # pylint: disable=too-few-public-methods
    """Base class for ValveManager objects.

    Expected to control the installation of flows into datapath tables.

    Ideally each datapath table should be controlled by 1 manager only."""

    _MISS_PRIORITY = 0
    _LOW_PRIORITY = 0x1000
    _MATCH_PRIORITY = 0x2000
    _LPM_PRIORITY = 0x3000
    _HIGH_PRIORITY = 0x4000
    _FILTER_PRIORITY = 0x5000

    def initialise_tables(self):
        '''initialise tables controlled by this manager'''
        return []

    def add_vlan(self, vlan):
        """install flows in response to a new vlan"""
        return []

    def add_port(self, port):
        """install flows in response to a new port"""
        return []

    def del_vlan(self, vlan):
        """delete flows in response to a vlan removal"""
        return []

    def del_port(self, port):
        """delete flows in response to a port removal"""
        return []
