"""Valve Manager base class"""

class ValveManagerBase(object):
    """Base class for ValveManager objects.

    Expected to control the installation of flows into datapath tables.

    Ideally each datapath table should be controlled by 1 manager only."""
    def initialise_tables(self):
        return []

    def add_vlan(self, vlan):
        return []
