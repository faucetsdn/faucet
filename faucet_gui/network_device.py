"""
PROGRAM_NAME: virtnet_creator
FILE_NAME: network_device.py
AUTHOR: Brendan Geoghegan
PROGRAM_DESCRIPTION:    This program is a GUI application for users to build or load network topologies that
have a SDN controller at their center.  The original code tied into a Xen loadout used to clone, startup, and
operate VMs, but this simplified version is only meant to visually generate network topologies and then generate
the requisite YAML files for a Faucet SDN controller.
FILE_DESCRIPTION: This file contains the class definitions for networking equipment.   Its is a
inheritance relationship class where the controller,switch,host all have some similar features.  As stated above
there is a lot of room of expansion here, this just lays out the shell for basic features of each device
"""


'''this is a class to track the individual interfaces on the switches'''
class Interface:
    def __init__(self, dev, band_bool):
        self.device = dev           # a reference pointer to whatever device is on the other end of the wire

        self.in_band = band_bool    # if True, then this interface will be on the in_band bridge
                                    # if False, then this interface is on the out_band bridge


'''Parent class that has inherited variables for all the subclasses'''
class NetworkDevice:
    def __init__(self, id_val, row_val, gui_label):
        self.id = id_val
        self.display_id = id_val
        self.ip_address = "192.168.1.1"
        self.netmask = "255.255.0.0"
        self.mac_address = "00:00:00:00:00:00"
        self.row = row_val
        self.icon = gui_label
        self.icon_id = id(gui_label)
        self.parent = None
        self.type = None


'''Child class definition to describe variables and function that the SDN controller would need'''
class Controller(NetworkDevice):
    def __init__(self, id_val, row_val, gui_label):
        NetworkDevice.__init__(self, id_val, row_val, gui_label)
        self.children = []
        self.next_switch_number = 1
        self.next_switch_ip = 1  # this is an attempt for distributing IP addresses
        self.type = "Controller"
        self.vlans = set([])

    '''helper function to determine if there are any children (switches) attached to this device'''
    def has_children(self):
        return False if not self.children else True

    '''cleanup function for when attached switches are deleted from the network'''
    def remove_child(self, child):
        for i in self.children:
            if child.id == i.id:
                self.children.remove(i)
                continue

    def shutdown(self):
        return


'''Child class definition to describe variables and function that the SDN enabled switch would need'''
class Switch(NetworkDevice):
    def __init__(self, id_val, row_val, gui_label):
        NetworkDevice.__init__(self, id_val, row_val, gui_label)
        self.children = []
        self.next_switch_number = 1
        self.next_host_number = 1
        self.type = "Switch"
        self.vlans = set([])
        self.controller_list = []
        self.interface_list = []    # keep track of all ethernet interfaces on the machine
        self.dp_id = None


    '''helper function to determine if there are any children (switches/hosts) attached to this device'''
    def has_children(self):
        return False if not self.children else True

    '''cleanup function for when children are deleted from the network'''
    def remove_child(self, child):
        for i in self.children:
            if child.id == i.id:
                self.children.remove(i)
                continue

        '''removes extra in/out of band connection from this device'''
        self.interface_list = [i for i in self.interface_list if i.device is not child]

    '''this helper function creates interface objects for each connection the switch makes'''
    def add_interface(self, dev, in_band):
        if dev.type == "Switch":
            if in_band:
                eth = Interface(dev, True)
            else:
                eth = Interface(dev, False)

        elif dev.type == "Controller":
            eth = Interface(dev, False)
        else:   #dev.type = Host
            eth = Interface(dev, True)

        self.interface_list.append(eth) # add to interface list

    '''numerous processes that should be shut down cleanly when closing the program'''
    def shutdown(self):
        return


'''Child class definition to describe variables and function that an endpoint host (PC/Laptop/Server/ect...)'''
class Host(NetworkDevice):
    def __init__(self, id_val, row_val, gui_label):
        NetworkDevice.__init__(self, id_val, row_val, gui_label)
        self.type = "Host"
        '''right now the default VLAN is 10, but this can be set manually in the system or changed here'''
        self.vlan = 10 #random.randint(1,10) * 10

    def shutdown(self):
        return
