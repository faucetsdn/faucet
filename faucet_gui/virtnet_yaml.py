"""
PROGRAM_NAME: virtnet_creator
FILE_NAME: main.py
AUTHOR: Brendan Geoghegan
PROGRAM_DESCRIPTION:    This program is a GUI application for users to build or load network topologies that
have a SDN controller at their center.  The original code tied into a Xen loadout used to clone, startup, and
operate VMs, but this simplified version is only meant to visually generate network topologies and then generate
the requisite YAML files for a Faucet SDN controller.
FILE_DESCRIPTION: This file contains functions to write a properly formatted YAML file that matches
what is currently showing on the virtnet_creator GUI. In order to use it, click file-> save yaml on the GUI menu.
"""


class yamlIO:
    def __init__(self):
        self.id = "YAML_IO"
        self.file = None

    '''function if writing to file on hosting gui machine'''
    def write_to_file(self, controller, file_name="faucet.yaml"):
        self.file = open(file_name, "w")
        self.__write(controller)
        self.file.close()

    '''initiates writing yaml file for each controller given'''
    def __write(self, controller):
        #print ("entering yaml write function")

        self.file.write("---\n")
        self.file.write("version: 2\n")
        self.file.write("dps:\n")

        '''faucet version has no bounds checking for empty switch list so need to add default NONE with a dp_id'''
        if len(controller.children) == 0:
            self.file.write("  NONE:\n")
            self.file.write("    dp_id: 0x1\n")
        else:
            for device in controller.children:
                self.__write_switch(device)

        self.file.write("vlans:\n")

        '''faucet version has no bounds checking for empty VLANS list so need to add default NONE'''
        if len(controller.vlans) == 0:
            self.file.write("  NONE:\n")
        else:    # else, write down all the associated VLANS
            sorted_vlans = sorted(controller.vlans)
            for vlan in sorted_vlans:
                self.file.write("  "+str(vlan)+":\n")
                self.file.write("    name: VLAN " + str(vlan)+"\n")

    '''recursive function that writes all the data for each switch in the yaml file'''
    def __write_switch(self, switch):

        self.file.write("  " + switch.id+":\n")
        self.file.write("    description: Switch-" + switch.id+"\n")
        self.file.write("    dp_id: " + "0x" + switch.dp_id+"\n")

        '''check if there are any in-band interfaces on this switch, as the current faucet version
        does not bounds check for empty interface listings'''
        no_in_band_connections = True
        for i in switch.interface_list:
            if i.in_band: no_in_band_connections = False
        if no_in_band_connections: return # old faucet version did no bounds checking if you include empty interfaces:

        self.file.write("    interfaces:\n")

        ovs_id = 1
        for i in switch.interface_list:
            if not i.in_band:   #we only care about in_band connections
                continue

            self.file.write("      "+str(ovs_id)+": # -> "+i.device.type +"- " +i.device.id+"\n")
            self.file.write("        description: Connection to " + i.device.id+"\n")
            ovs_id += 1
            if i.device.type == "Switch":
                tagged_vlans = "        tagged_vlans: ["
                sorted_vlans = sorted(i.device.vlans)
                for vlan in sorted_vlans:
                    tagged_vlans += str(vlan) + ", "
                tagged_vlans = tagged_vlans.rstrip(", ")+"]"
                self.file.write(tagged_vlans+"\n")
            else:
                self.file.write("        native_vlan: " + str(i.device.vlan)+"\n")

        for device in switch.children:
            if device.type == "Switch":
                self.__write_switch(device)
