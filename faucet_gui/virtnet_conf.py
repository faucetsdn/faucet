"""
PROGRAM_NAME: virtnet_creator
FILE_NAME: conf.py
AUTHOR: Brendan Geoghegan
PROGRAM_DESCRIPTION:    This program is a GUI application for users to build or load network topologies that
have a SDN controller at their center.  The original code tied into a Xen loadout used to clone, startup, and
operate VMs, but this simplified version is only meant to visually generate network topologies and then generate
the requisite YAML files for a Faucet SDN controller.
FILE_DESCRIPTION: This file contains functions to read and write a custom config file for saving and loading
a specific network configuration.  In theory this would allow users to quickly spin up the same network environment
over and over again.  Right now the file type is saves as .virtnet, you can find this being called from main.py.
"""


class confIO:
    def __init__(self):
        self.id = "YAML_IO"
        self.file = None
        self.device_dictionary = {}
        self.parent = None
        self.host = None

    '''Initiate a series of read functions going through the .virtnet file and creating instances of devices'''
    def read(self, filename, sdn_widget):
        # print ("entering config read function")
        self.file = open(filename, "r")

        '''check the first and last line of the file for good formatting'''
        if self.file.readline() != "Row 0 : Controller\n":
            print "First line of config file is not correct"
            return
        for line in self.file:
            pass
        if line != "END_CONNECTION_LIST\n":
            print "Last line of config file is not correct"
            return

        self.file.seek(0,0) #reset file reader
        line = self.file.readline()
        self.device_dictionary = {}

        '''first we read in all the equipment and populate our program'''
        while line != "END_ASSET_LIST\n":
            if line.split(':').__len__() != 2:
                line = self.file.readline()
                continue
            else:
                device_type = line.split(':')[1].strip()

            if device_type == "Controller":
                self.__read_controller(sdn_widget)

            elif device_type == "Switch" or device_type == "Host":
                device_row = int(line.split(":")[0].strip("Row "))  #rows help determine parents

                while device_row <= self.parent.row:    # move back up the tree until you find the next parent
                    self.parent = self.parent.parent

                if device_type == "Switch":
                    self.__read_switch(sdn_widget)

                elif device_type == "Host":
                    self.__read_host(sdn_widget)

            line = self.file.readline()

        '''read in all the in/out of band connections, assigned controllers, and vlans'''
        self.__read_connections()

        self.device_dictionary.clear()  # done using this, time to clean
        self.file.close()               # and close file

    '''Function to read controller information from .virtnet file and to instantiate new controller objects'''
    def __read_controller(self, sdn_widget):
        self.parent = sdn_widget.add_controller()
        line = self.file.readline()
        while line.split(':')[0].strip() != "END":
            line_in = line.split(':')
            if line_in[0].strip() == 'ID': self.parent.id = line_in[1].strip()
            if line_in[0].strip() == 'DISPLAY_ID': self.parent.display_id = line_in[1].strip()
            if line_in[0].strip() == 'IP_ADDR': self.parent.ip_address = line_in[1].strip()
            if line_in[0].strip() == 'NETMASK': self.parent.netmask = line_in[1].strip()
            if line_in[0].strip() == 'MAC_ADDR':
                mac = line_in[1].strip()
                self.parent.mac_address = ':'.join([mac[i:i + 2] for i in range(0, len(mac), 2)])  # puts :'s in mac_adr
            if line_in[0].strip() == 'Next_Switch_Num': self.parent.next_switch_number = int(line_in[1].strip())

            line = self.file.readline()
        self.device_dictionary[self.parent.mac_address] = self.parent # this is used to quickly check mac addrs later

    '''Function to read switch information from .virtnet file and to instantiate new controller objects'''
    def __read_switch(self, sdn_widget):
        self.parent.next_switch_number -= 1  # due to how the system adds switches in the first place
        self.parent = sdn_widget.add_switch(self.parent)
        line = self.file.readline()
        while line.split(':')[0].strip() != "END":
            line_in = line.split(':')
            if line_in[0].strip() == 'ID': self.parent.id = line_in[1].strip()
            if line_in[0].strip() == 'DISPLAY_ID': self.parent.display_id = line_in[1].strip()
            if line_in[0].strip() == 'IP_ADDR': self.parent.ip_address = line_in[1].strip()
            if line_in[0].strip() == 'NETMASK': self.parent.netmask = line_in[1].strip()
            if line_in[0].strip() == 'MAC_ADDR':
                mac = line_in[1].strip()
                self.parent.mac_address = ':'.join([mac[i:i + 2] for i in range(0, len(mac), 2)])  # puts :'s in mac_adr
            if line_in[0].strip() == 'DP_ID': self.parent.dp_id = line_in[1].strip()
            if line_in[0].strip() == 'Next_Switch_Num': self.parent.next_switch_number = int(line_in[1].strip())
            if line_in[0].strip() == 'Next_Host_Num': self.parent.next_host_number = int(line_in[1].strip())

            line = self.file.readline()
        self.device_dictionary[self.parent.mac_address] = self.parent  # this is used to quickly check mac_addrs later

    '''Function to read host information from .virtnet file and to instantiate new controller objects'''
    def __read_host(self, sdn_widget):
        self.parent.next_host_number -= 1  # due to how the system adds switches in the first place
        host = sdn_widget.add_host(self.parent)
        line = self.file.readline()
        while line.split(':')[0].strip() != "END":
            line_in = line.split(':')
            if line_in[0].strip() == 'ID': host.id = line_in[1].strip()
            if line_in[0].strip() == 'DISPLAY_ID': host.display_id = line_in[1].strip()
            if line_in[0].strip() == 'IP_ADDR': host.ip_address = line_in[1].strip()
            if line_in[0].strip() == 'NETMASK': host.netmask = line_in[1].strip()
            if line_in[0].strip() == 'MAC_ADDR':
                mac = line_in[1].strip()
                host.mac_address = ':'.join([mac[i:i + 2] for i in range(0, len(mac), 2)])  # puts :'s in mac_adr
            if line_in[0].strip() == 'VLAN' : host.vlan = int(line_in[1].strip())
            line = self.file.readline()
        self.device_dictionary[host.mac_address] = host  # this is used to quickly check s later

    '''read in all the in/out of band connections, controller relations, and vlans to create links'''
    def __read_connections(self):
        # clear any connections that would have been automatically added in equipment population
        for i in self.device_dictionary:
            if self.device_dictionary[i].type == "Switch":
                tmp_switch = self.device_dictionary[i]
                tmp_switch.interface_list[:] = []
                tmp_switch.controller_list[:] = []
                tmp_switch.vlans.clear()

                tmp_switch.next_eth_num = 1  # counter for naming the next ethX added
                tmp_switch.next_in_band_num = 1  # counter for naming the next in_band connection
                tmp_switch.next_out_band_num = 1  # counter for naming the next out_band connection

            elif self.device_dictionary[i].type == "Controller":
                self.device_dictionary[i].vlans.clear()

        line = self.file.readline()
        while line != "END_CONNECTION_LIST\n":

            connection = line.split(":")[0].strip()
            mac_a = line.split(":")[1].strip()
            mac_a = ':'.join([mac_a[i:i + 2] for i in range(0, len(mac_a), 2)])  # puts :'s in mac addr
            mac_b = line.split(":")[2].strip()
            mac_b = ':'.join([mac_b[i:i + 2] for i in range(0, len(mac_b), 2)])  # puts :'s in mac addr

            if connection == "In_Band":
                self.device_dictionary[mac_a].add_interface(self.device_dictionary[mac_b], True)
            elif connection == "Out_Band":
                self.device_dictionary[mac_a].add_interface(self.device_dictionary[mac_b], False)
            elif connection == "Assigned_Controller":
                self.device_dictionary[mac_a].controller_list.append(self.device_dictionary[mac_b])
            elif connection == "Vlans":
                vlan_list = mac_b.split()
                for i in vlan_list:
                    self.device_dictionary[mac_a].vlans.add(i.strip())

            line = self.file.readline()

    '''Initiate a series of write functions going through the list of devices and pulling out info'''
    def write(self, filename, controller_list, switch_list):
        # print ("entering config write function")
        if controller_list is None:
            return

        self.file = open(filename,"w")
        for c in controller_list:
            self.file.write("Row 0 : Controller\n")
            self.__write_controller(c)

        self.file.write("END_ASSET_LIST\n")

        for s in switch_list:
            self.__write_switch_connections(s)

        for c in controller_list:
            self.__write_controller_vlans(c)

        self.file.write("END_CONNECTION_LIST\n")
        self.file.close()

    '''Function to write controller information to a .virtnet file'''
    def __write_controller(self, c):

        self.file.write("ID : "+ c.id+"\n")
        self.file.write("DISPLAY_ID :"+ c.display_id+"\n")
        self.file.write("IP_ADDR : "+ c.ip_address+"\n")
        self.file.write("NETMASK : "+ c.netmask+"\n")
        self.file.write("MAC_ADDR : " + str(c.mac_address).replace(':','') + "\n")
        self.file.write("Next_Switch_Num : "+ str(c.next_switch_number)+"\n")
        v_lan_string = " "
        for i in c.vlans:
            v_lan_string += str(i)+" "
        self.file.write("V_LAN : " + v_lan_string + "\n")
        self.file.write("END : Controller\n")

        for s in c.children:
            self.__write_switch(s)

    '''Function to write switch information and any attached hosts information to a .virtnet file'''
    def __write_switch(self, s):

        self.file.write("Row "+ str(s.row) + " : Switch\n")
        self.file.write("ID : "+ s.id+"\n")
        self.file.write("DISPLAY_ID :" + s.display_id+"\n")
        self.file.write("IP_ADDR : "+ s.ip_address+"\n")
        self.file.write("NETMASK : " + s.netmask + "\n")
        self.file.write("MAC_ADDR : "+ str(s.mac_address).replace(":",'')+"\n")
        self.file.write("DP_ID : " + s.dp_id + "\n")
        self.file.write("Next_Switch_Num : "+ str(s.next_switch_number)+"\n")
        self.file.write("Next_Host_Num : "+ str(s.next_host_number)+"\n")
        self.file.write("END : Switch\n")

        for child in s.children:
            if child.type == "Host":
                self.file.write("Row " + str(child.row) + " : Host\n")
                self.file.write("ID : "+ child.id + "\n")
                self.file.write("DISPLAY_ID :" + child.display_id+"\n")
                self.file.write("IP_ADDR : "+ child.ip_address + "\n")
                self.file.write("NETMASK : " + child.netmask + "\n")
                self.file.write("MAC_ADDR : " + str(child.mac_address).replace(':','') + "\n")
                self.file.write("VLAN : " + str(child.vlan) + "\n")
                self.file.write("END : Host\n")
            else:
                self.__write_switch(child)

    '''Function to capture all the links (In/Out band) from each switch to write to .virtnet file'''
    def __write_switch_connections(self, s):
        s_mac = str(s.mac_address).replace(':','')
        for i in s.interface_list:
            if i.in_band:
                self.file.write("In_Band: " + s_mac + " : " + str(i.device.mac_address).replace(':', '') + "\n")
            else:
                self.file.write("Out_Band: " + s_mac + " : " + str(i.device.mac_address).replace(':', '') + "\n")

        for i in s.controller_list:
            self.file.write("Assigned_Controller: " + s_mac + " : " + str(i.mac_address).replace(':','') + "\n")
        vlan_string = "Vlans : " + s_mac + " : "
        for i in s.vlans:
            vlan_string += str(i) + ' '
        self.file.write(vlan_string + '\n')

    '''Function to capture the VLAN data from a controller and add to the end of the file'''
    def __write_controller_vlans(self, c):
        c_mac= str(c.mac_address).replace(':','')
        vlan_string = "Vlans : " + c_mac + " : "
        for i in c.vlans:
            vlan_string += str(i) + ' '
        self.file.write(vlan_string + '\n')