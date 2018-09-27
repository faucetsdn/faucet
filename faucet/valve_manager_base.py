"""Valve Manager base class"""

# pylint: disable=R0201
# pylint: disable=W0613
class ValveManagerBase:
    """Base class for ValveManager objects.

    Expected to control the installation of flows into datapath tables.

    Ideally each datapath table should be controlled by 1 manager only."""

    _MISS_PRIORITY = 0
    _LOW_PRIORITY = 0x1000
    _STATIC_MATCH_PRIORITY = 0x2000
    _LPM_PRIORITY = 0x3000
    _HIGH_PRIORITY = 0x4000
    _FILTER_PRIORITY = 0x5000

    def initialise_tables(self):
        """initialise tables for this manager.

        returns:
            list of ofmsgs"""
        return []

    def add_vlan(self, vlan):
        """update tables for the addition of a vlan

        returns:
            list of ofmsgs"""
        return []

    def add_port(self, port):
        """update tables for the addition of a port

        returns:
            list of ofmsgs"""
        return []

    def del_vlan(self, vlan):
        """update tables for the removal of a vlan

        returns:
            list of ofmsgs"""
        return []

    def del_port(self, port):
        """update tables for the removal of a port

        returns:
            list of ofmsgs"""
        return []
