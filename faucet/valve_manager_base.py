"""Valve Manager base class"""

# pylint: disable=R0201
# pylint: disable=W0613
class ValveManagerBase: # pylint: disable=too-few-public-methods
    """Base class for ValveManager objects.

    Expected to control the installation of flows into datapath tables.

    Ideally each datapath table should be controlled by 1 manager only."""

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
