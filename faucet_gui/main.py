#!/usr/bin/env python
# # -*- coding: utf-8 -*-

"""
PROGRAM_NAME: virtnet_creator
FILE_NAME: main.py
AUTHOR: Brendan Geoghegan
PROGRAM_DESCRIPTION:    This program is a GUI application for users to build or load network topologies that
have a SDN controller at their center.  The original code tied into a Xen loadout used to clone, startup, and
operate VMs, but this simplified version is only meant to visually generate network topologies and then generate
the requisite YAML files for a Faucet SDN controller.
FILE_DESCRIPTION: This file sets up and runs the primary GUI that users will interact with.  Menus are
context driven by right clicking on each device.  You can add multiple controllers, switches, and hosts but right now
each host is only allowed to be tethered to one switch.  Device names, MAC addresses,  and IP addresses are
automatically allocated to each machine.  All the IPs, MAC, VLANs, and device names can be changed within the program
or though a save file specific to this program.
"""

import sys                      # We need sys so that we can pass argv to QApplication
import os.path                  # used to verify icon files exist in the local filesystem
import socket                   # using this to validate IP addresses

from PyQt4.QtCore import *
from PyQt4.QtGui import *

from network_device import *    # class definitions for controller, switch, host
from virtnet_conf import *      # class for reading/writing custom config files for this program
import virtnet_yaml             # class for saving YAML files onto the controller or to file

WIDTH = 1000                    # primary application window size definitions
HEIGHT = 900
ALLOWABLE_ROWS = 10             # used to set how many rows deep the network is allowed to be (CAN BE CHANGED HERE)
ICON_PATH = "pictures/"
ICON_FILES = ["controller_dev.png", "host_dev.png", "switch_dev.png"]


'''-------------------------CLASS DEFINITIONS-------------------------------------------------------'''


'''Used as an object type for painting lines'''
class Line():
    def __init__(self, p1, p2, col=Qt.black):
        self.pnt1 = p1
        self.pnt2 = p2
        self.color = col


'''Used as an object type for displaying the gui icons inside the frame'''
class IconWidget(QWidget):
    def __init__(self):
        super(IconWidget, self).__init__()
        self.lineList = []
        self.active_flag = False
        '''Trying to modify colors'''

        custom_blue = QColor(145, 145, 200, 127)  # a color I like for the initial background
        custom_blue.setHsv(240, 85, 218) # setting the HueSatVal
        self.pal = QPalette()   # A custom palette for the app
        self.pal.setColor(QPalette.Background, custom_blue)
        self.setPalette(self.pal)  # set palette to this widget
        self.setWindowModality(Qt.NonModal)

    '''predefined function in PyQt for drawing objects.  Gets called with .update()'''
    def paintEvent(self, event):
        painter = QPainter(self)
        '''black lines are smaller than green in case of overlap you can still see both'''
        for line in self.lineList:
            if line.color == Qt.green: painter.setPen(QPen(Qt.green, 5))
            else: painter.setPen(QPen(Qt.black, 3))
            painter.drawLine(line.pnt1, line.pnt2)

    '''used to remove lines between screen updates'''
    def clear_lines(self):
        self.lineList[:] = []

    '''change color of main screen background'''
    def set_background_color(self, color):
        self.pal.setColor(QPalette.Background, color)
        self.setPalette(self.pal)
        self.update()


'''Primary widget in the application keeps track of menus, network devices, and configurations'''
class SdnWidget(QMainWindow):
    def __init__(self):

        super(SdnWidget, self).__init__()
        self.resize(WIDTH, HEIGHT)
        self.setWindowTitle("SDN Network Gui Creator")

        self.central_widget = IconWidget()                  # create widget we will use for layout management
        self.vertical_layout = None                         # instantiated in __display_startup
        self.scroll_widget = QScrollArea()                  # create widget used for scrolling

        self.scroll_widget.setWidget(self.central_widget)   # place the layout onto the scrolling widget
        self.scroll_widget.setWidgetResizable(True)
        self.scroll_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.scroll_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.scroll_widget.horizontalScrollBar().rangeChanged.connect(self.__update_entire_gui) # update screen if h_scrollbar changes
        self.scroll_widget.verticalScrollBar().rangeChanged.connect(self.__update_entire_gui)   # update screen if v_scrollbar changes
        self.setCentralWidget(self.scroll_widget)           # set the central widget as the scrolling one
        self.statusbar = self.statusBar()            # initializes the QMainWindow status bar for use later

        self.controller_id_number = 1   # used for tracking what controllers exist
        self.controller_list = []   # list of all controllers in the program

        self.switch_list = []       # switches
        self.host_list = []         # hosts
        self.row_list = []          # list of each QHBox row_list that we use to layout the device icons

        self.yaml = virtnet_yaml.yamlIO()   # instance of yaml for saving the current status
        self.conf = confIO()        # instance of custom config file reader/writer


        self.loading_mode_bool = False      # Boolean to know if loading a configuration from file
        self.show_labels_bool = True        # Boolean for showing labels
        self.add_connection_bool = False    # Boolean tracker for user adding custom connection between switches
        self.add_connection_switch = None   # user selected object for adding custom connection between switches


        self.__check_file_dependencies()    # make sure the following files exist locally before loading them
        self.controller_icon = QPixmap(ICON_PATH+ICON_FILES[0]).scaled(200,122)
        self.host_icon = QPixmap(ICON_PATH + ICON_FILES[1]).scaled(75, 75)
        self.switch_icon = QPixmap(ICON_PATH + ICON_FILES[2]).scaled(200, 100)


        self.__display_startup()    # load all the primary graphics layout instances
        self.__menu_startup()       # load all the top_menu options

        self.add_controller()       # start the program with a single controller

        self.statusbar.showMessage("Created by: Brendan Geoghegan ~ Enjoy", 3000)              # candy

    '''Private function for checking existence of icon files before starting program'''
    def __check_file_dependencies(self):
        error_string = ""
        details_string = ""
        if not os.path.exists(ICON_PATH):
            error_string += "Missing a "+ICON_PATH+ " folder\n"
            details_string += "Need to add a folder where main.py is called " + ICON_PATH+"\n"
        for icon in ICON_FILES:
            if not os.path.isfile(ICON_PATH+icon):
                error_string += "Missing a "+icon+" file\n"
                details_string += "Need to add an icon files in "+ICON_PATH+" called "+icon+"\n"

        if error_string:
            error_message("Cannot load the icon files for the application", error_string, details_string)
            sys.exit()

    '''Private function for top file menu and corresponding actions'''
    def __menu_startup(self):

        '''Top menu options'''
        main_menu = self.menuBar()
        file_menu = main_menu.addMenu('&File')
        edit_menu = main_menu.addMenu('&Edit Network')
        display_menu = main_menu.addMenu('&Display')

        '''Sub menu options under each of the above categories.  Each includes a shortcut and status-tip'''

        save_yaml_action = QAction("Export to Faucet .YAML", self)
        save_yaml_action.setShortcut("Ctrl+Y")
        save_yaml_action.setStatusTip('Saves Faucet SDN controller configurations yaml file')
        save_yaml_action.triggered.connect(self.__save_controller_yaml)
        file_menu.addAction(save_yaml_action)

        save_conf_action = QAction("Save config file", self)
        save_conf_action.setShortcut("Ctrl+S")
        save_conf_action.setStatusTip('Saves a .virtnet configuration file for this network layout')
        save_conf_action.triggered.connect(self.__save_configuration)
        file_menu.addAction(save_conf_action)

        load_conf_action = QAction("Load config file", self)
        load_conf_action.setShortcut("Ctrl+O")
        load_conf_action.setStatusTip('Opens a .virtnet configuration file and configures network')
        load_conf_action.triggered.connect(self.__load_configuration)
        file_menu.addAction(load_conf_action)

        exit_action = QAction("Exit Program", self)
        exit_action.setShortcut("Alt+F4")
        exit_action.setStatusTip('Closes program -does not save anything')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        add_controller_action = QAction("Add Controller", self)
        add_controller_action.setShortcut("Ctrl+C")
        add_controller_action.setStatusTip('Adds a root level controller')
        add_controller_action.triggered.connect(self.add_controller)
        edit_menu.addAction(add_controller_action)

        wipe_network_action = QAction("Delete Entire Network", self)
        wipe_network_action.setShortcut("Ctrl+D")
        wipe_network_action.setStatusTip('Deletes entire current network')
        wipe_network_action.triggered.connect(self.__wipe_network)
        edit_menu.addAction(wipe_network_action)

        show_label_action = QAction("Show/Hide Labels", self)
        show_label_action.setShortcut("Ctrl+L")
        show_label_action.setStatusTip('Show or hide the labels on each device')
        show_label_action.triggered.connect(self.__config_labels)
        display_menu.addAction(show_label_action)

        color_selection_action = QAction("Change Background Color", self)
        color_selection_action.setShortcut("Ctrl+B")
        color_selection_action.setStatusTip('Pick a custom color for the main screen background')
        color_selection_action.triggered.connect(self.__color_selector)
        display_menu.addAction(color_selection_action)

        show_tree_action = QAction("View VLAN Report", self)
        show_tree_action.setShortcut("Ctrl+V")
        show_tree_action.setStatusTip('Generate a report for Hosts in VLANS')
        show_tree_action.triggered.connect(self.__vlan_report)
        display_menu.addAction(show_tree_action)

    '''Private function used to initiate the grid layout'''
    def __display_startup(self):
        self.vertical_layout = QVBoxLayout(self.central_widget)
        self.vertical_layout.setAlignment(Qt.AlignTop)

        '''Create 10 levels deep for the network'''
        for i in range(ALLOWABLE_ROWS):
            row = QHBoxLayout()                 # horizontal layout
            row.setAlignment(Qt.AlignCenter)
            self.vertical_layout.addLayout(row)
            self.row_list.append(row)

    '''Private function used to supplement clearing labels'''
    def __refresh_pixmaps(self):
        for i in self.controller_list:
            i.icon.setPixmap(self.controller_icon)
        for i in self.switch_list:
            i.icon.setPixmap(self.switch_icon)
        for i in self.host_list:
            i.icon.setPixmap(self.host_icon)

    '''Public drawn function overloading PyQt baseline gets called on self.update()'''
    def paintEvent(self, event):

        if self.central_widget.active_flag:
            self.central_widget.clear_lines()  # clear old lines
            self.__calculate_lines()  # calculate new lines
            self.central_widget.update()  # display new lines

        #Paint labels for all the devices if the setting is on
        if self.show_labels_bool:
            self.__refresh_pixmaps()
            font = QFont()
            for i in self.controller_list:
                painter = QPainter(i.icon.pixmap()) # change to paint inside the icon
                font.setPointSizeF(50)  # scale for length of asset name
                painter.setFont(font)
                painter.drawText(QPoint(37,60), i.display_id)

            for i in self.switch_list:
                painter = QPainter(i.icon.pixmap()) # change to paint inside the icon
                if i.row < 10:
                    font.setPointSizeF(20)  # scale for length of asset name
                else:
                    font.setPointSizeF(2)
                painter.setFont(font)
                painter.drawText(QPoint(50,42), i.display_id)

            for i in self.host_list:
                painter = QPainter(i.icon.pixmap()) # change to paint inside the icon
                if i.row < 7:
                    font.setPointSizeF(9)  # scale for length of asset name
                else:
                    font.setPointSizeF(2)
                painter.setFont(font)
                painter.drawText(QPoint(8,42), i.display_id)

    '''Private update function for updating all elements of the GUI screen'''
    def __update_entire_gui(self):
        self.central_widget.active_flag = True
        self.update()

    '''Used to calculate all the lines that need to be drawn'''
    def __calculate_lines(self):

        '''cycle through each switch and look at the attached interfaces
           for each connection and depending on type, add a line in the graphic'''
        for switch in self.switch_list:
            point_a = switch.icon.geometry().topLeft() + QPoint(100, 60)
            for i in switch.interface_list:
                dev = i.device
                if dev.type == "Host":
                    point_b = dev.icon.geometry().topLeft() + QPoint(30, 27)
                    self.central_widget.lineList.append(Line(point_a, point_b, Qt.green))
                elif dev.type == "Controller":
                    point_b = dev.icon.geometry().topLeft() + QPoint(100, 100)
                    self.central_widget.lineList.append(Line(point_a, point_b, Qt.black))
                elif dev.type == "Switch":
                    if i.in_band:
                        point_b = dev.icon.geometry().topLeft() + QPoint(100, 60)
                        self.central_widget.lineList.append(Line(point_a, point_b, Qt.green))
                    else:
                        point_b = dev.icon.geometry().topLeft() + QPoint(110, 65)
                        self.central_widget.lineList.append(Line(point_a + QPoint(10, 5), point_b, Qt.black))

    '''Private function to determine where to insert a new device in a the row_list layout so the tree is sorted'''
    def __find_insert_location(self, row_num, parent_icon_id):
        p_index = 0
        insert_id = 0
        row_equipment_list = []

        if self.row_list[row_num+1].count() == 0:  # if nothing in the next row_list put in 0 element place
            return 0

        # create a temp list of all the equipment on that row_list
        for i in range(self.row_list[row_num].count()):
            for j in self.controller_list:
                if j.icon_id == id(self.row_list[row_num].itemAt(i).widget()):
                    row_equipment_list.append(j)
            for j in self.switch_list:
                if j.icon_id == id(self.row_list[row_num].itemAt(i).widget()):
                    row_equipment_list.append(j)

        # match the parent_icon to the equipment object
        for i in range(row_equipment_list.__len__()):
            if row_equipment_list[i].icon_id == parent_icon_id:
                p_index = i

        if row_equipment_list[p_index].has_children():     # if this parent already has children put it there
            insert_id = row_equipment_list[p_index].children[-1].icon_id
        elif p_index == 0:                      # if no children and front of row_list put in 0 element place
            return 0
        else:                                   # else find closest neighbor and put at the end of their list
            for i in range(1, p_index+1):
                if row_equipment_list[p_index - i].has_children():
                    insert_id = row_equipment_list[p_index - i].children[-1].icon_id
                    break

        for i in range(self.row_list[row_num+1].count()):
            if insert_id == id(self.row_list[row_num+1].itemAt(i).widget()):
                return i+1

        return 0    # if all the neighbors to your left do not have children then put it in the 0th spot

    '''Public function to add new controllers to the system, not private because used by virtnet_conf.py'''
    def add_controller(self):

        new_label = QLabel(self.centralWidget()) # creates a pyQt object we can place an icon on
        new_label.setObjectName(str(id(new_label))) # places a label on that icon for the controller name
        new_label.setPixmap(self.controller_icon) # places the pixmap on the icon to represent the controller
        new_controller = Controller("C" + str(self.controller_id_number), 0, new_label) # see network_device.py

        new_controller.ip_address = "11."+str(self.controller_id_number)+".1.1" # default 11.x.x.x for network
        '''next two lines create a default mac address based on controller id number to go up to C999'''
        mac = str('0' * (3 - len(str(self.controller_id_number))) + 'C' + str(self.controller_id_number))
        new_controller.mac_address = "00:"+ mac[:2] + ':' + mac[2:] + ':00' * 3
        self.controller_id_number += 1 # keeps track for adding new controllers
        self.row_list[0].addWidget(new_controller.icon) # this manages what devices are in what row
        self.controller_list.append(new_controller) # keep a running tally of all the controllers spawned


        '''At this point we have only created controller object, not the virtualized instance'''
        if self.loading_mode_bool:  # if in loading mode just return the object
            return new_controller

        self.__update_entire_gui()  # this will updates the new icon and lines

    '''Public function to add new switch to the system, not private because used by virtnet_conf.py '''
    def add_switch(self, parent):

        new_label = QLabel(self.centralWidget())        # QLabel created for the representative icon
        new_label.setPixmap(self.switch_icon)       # Assign it the switch pixelmap
        switch_id_num = None                            # This is used for the label, IP address, and DPID

        '''initialize switch object and assign default controllers and connections from parent'''
        if parent.type == "Controller":
            switch_id_num = parent.next_switch_number
            new_switch = Switch(parent.id + "_S" + str(switch_id_num), parent.row + 1, new_label)
            new_switch.parent = parent
            parent.next_switch_number += 1
            new_switch.controller_list.append(parent)

        elif parent.type == "Switch":
            switch_id_num = parent.controller_list[0].next_switch_number
            new_switch = Switch(parent.controller_list[0].id + "_S" + str(switch_id_num), parent.row + 1, new_label)
            new_switch.parent = parent
            parent.controller_list[0].next_switch_number += 1

            for i in parent.controller_list:    # grab whatever controllers the parent was assigned to
                new_switch.controller_list.append(i)

            '''add interfaces for in/out band connections for the new switch and parent'''
            new_switch.add_interface(parent, True) # True is in_band
            parent.add_interface(new_switch, True)
            parent.add_interface(new_switch, False) # False is out_of_band

        new_switch.add_interface(parent, False) # adds a link to the device

        '''this code is an attempt at assigning unique IP addresses (limited to 253 switches per controller)
            the schema is 11.XXX.YYY.1 where XXX is the controllers digits and YYY is the switch_id+1'''
        new_switch.ip_address = str(new_switch.controller_list[0].ip_address.rsplit('.',2)[0] + '.' +
                                str(switch_id_num%253+1) + ".1")

        '''next three lines create a default mac address and dpid based on 00:controller_id:switch_id+0:00'''
        mac = str('0' * (3 - len(str(switch_id_num))) + str(switch_id_num))
        new_switch.mac_address = new_switch.controller_list[0].mac_address[:9]+mac[:2] + ':' + mac[2:] + '0:00'
        new_switch.dp_id = '0000'+new_switch.mac_address.replace(':','') # setting dpid as mac + 4 bytes of zero

        '''this code handles placing the icon onto the screen in the correct location'''
        i_loc = self.__find_insert_location(parent.row, parent.icon_id)
        self.row_list[parent.row + 1].insertWidget(i_loc, new_switch.icon)
        self.switch_list.append(new_switch)

        parent.children.append(new_switch)

        '''At this point we have only created switch object, not the virtualized instance'''
        if self.loading_mode_bool: # if in loading mode just return the object
            return new_switch

        self.__update_entire_gui() # this will updates the new icon and lines

    '''Private function to add up to 250 hosts on a switch'''
    def __add_multiple_hosts(self, parent, pos):
        msg = QMessageBox()
        msg.move(pos)
        msg.setStandardButtons(QMessageBox.Cancel | QMessageBox.Apply)
        msg.setDefaultButton(QMessageBox.Apply)
        layout = msg.layout()

        '''The following adds display and input elements to the modification box lots of 
        magic numbers because there was no simpler or cleaner way to do this with the addWidget 
        function and still have the elements show side by side'''
        msg.setWindowTitle("Multiple Host Addition Menu")
        layout.addWidget(QLabel("Please type a number 1-250", msg), 0, 0, 1, 2)
        layout.addWidget(QLabel("-" * 50, msg), 1, 0, 1, 2)
        layout.addWidget(QLabel("", msg))  # spacing because I cant move the apply button

        name_edit = QLineEdit()
        name_edit.setText('1')
        layout.addWidget(QLabel("Number of hosts to add:", msg), 3, 0)
        layout.addWidget(name_edit, 3, 1)

        result = msg.exec_()  # launch modification menu

        '''Now we look to use the results'''
        if result == QMessageBox.Apply:
            try:  # new name validity checks would go here
                number_of_hosts = int(str(name_edit.text()))
                if number_of_hosts < 1 : raise ValueError("Less than 1")
                if number_of_hosts > 250 : raise ValueError("Input greater than 250")
                if parent.next_host_number + number_of_hosts > 250 : raise ValueError("Would lead to more than 250 hosts on switch")

                for i in range(number_of_hosts):
                    self.add_host(parent)
            except ValueError as err:
                error_message("Must be an integer value between 1-250\n" + err[0])


            self.__update_entire_gui()  # since the name has been changed on the screen

    '''Public function to add new host to the system, not private because used by virtnet_conf.py'''
    def add_host(self, parent):

        new_label = QLabel(self.centralWidget())
        new_label.setPixmap(self.host_icon)
        host_id_num = parent.next_host_number
        new_host = Host(parent.id + "_H" + str(host_id_num), parent.row + 1, new_label)
        new_host.parent = parent

        '''this sets the ip address in the schema 12.X.Y.Z: X=controller_id, Y=switch_id+1, Z=host_id+1'''
        new_host.ip_address = str('12.' + parent.ip_address.rsplit('.', 1)[0].split('.', 1)[1] + '.' +
                                str(host_id_num % 253 + 1))

        '''next two lines create a default mac address based on 00:controller_id:switch_id+host_id'''
        mac = str('0' * (3 - len(str(host_id_num))) + str(host_id_num))
        new_host.mac_address = new_host.parent.mac_address[:13] + mac[0] + ':' + mac[1:]

        '''this is to populate VLAN data on the network when a new host is added'''
        self.__add_v_lan(parent, new_host.vlan)

        parent.next_host_number += 1
        i_loc = self.__find_insert_location(parent.row, parent.icon_id)
        self.row_list[parent.row + 1].insertWidget(i_loc, new_host.icon)
        self.host_list.append(new_host)
        parent.children.append(new_host)


        parent.add_interface(new_host, True) # add an in-band interface to the host's parent switch

        '''At this point we have only created host object, not the virtualized instance'''
        if self.loading_mode_bool: # if in loading mode then just return the object
            return new_host

        self.__update_entire_gui()  # this will updates the new icon and lines

    '''Private function to propagate VLAN data on the network when a new host is added'''
    def __add_v_lan(self, switch, vlan):
        switch.vlans.add(vlan)
        for i in switch.controller_list:
            i.vlans.add(vlan)
        for i in switch.interface_list:
            if i.in_band and i.device.type == "Switch" and i.device.row < switch.row:
                self.__add_v_lan(i.device, vlan)

    '''Private function to add a new connection from a switch to another device'''
    def add_connection(self, device_a, device_b, pos):
        in_band = False      # track if there was an in_band connection already
        out_band = False     # track if there was an out_band connection already

        for i in device_a.interface_list:
            if i.device == device_b: # see if there is already a connection in the interface list
                if i.in_band: in_band = True   # in_band?
                else: out_band = True          # must be out-of-band

        if device_b.type == "Host":
            if in_band: error_message("You have already connected to this host")
            else: error_message("Hosts are only allowed one connection")
            return
        elif device_b.type == "Controller":
            if out_band: error_message("You have already connected to this controller")
            else:
                device_a.add_interface(device_b, False)  # Add the connection
                if device_b not in device_a.controller_list:
                    device_a.controller_list.append(device_b) # If not already on the controller list, add it
        elif device_b.type == "Switch":
            if in_band and not out_band:
                device_a.add_interface(device_b, False)  # Add the connection
                device_b.add_interface(device_a, False)  # Add the connection
            elif out_band and not in_band:
                device_a.add_interface(device_b, True)  # Add the connection
                device_b.add_interface(device_a, True)  # Add the connection
            elif in_band and out_band: error_message("You have already fully connected to this switch")
            else:
                msg = self.__connection_radio_message(self.mapToGlobal(pos()))
                if msg == "in_band":
                    device_a.add_interface(device_b, True)  # Add the connection
                    device_b.add_interface(device_a, True)  # Add the connection
                elif msg == "out_band":
                    device_a.add_interface(device_b, False)  # Add the connection
                    device_b.add_interface(device_a, False)  # Add the connection
                elif msg == "both_band":
                    device_a.add_interface(device_b, True)  # Add the connection
                    device_b.add_interface(device_a, True)  # Add the connection
                    device_a.add_interface(device_b, False)  # Add the connection
                    device_b.add_interface(device_a, False)  # Add the connection

        for i in device_a.vlans:
            self.__add_v_lan(device_a, i)

        self.__update_entire_gui()

    '''Private context menu for controller'''
    def __controller_menu(self, pos, controller_obj):

        menu = QMenu(self)  # toplevel menu item
        info_action = menu.addAction("Display Info")
        add_menu = menu.addMenu("Add")
        add_switch_action = add_menu.addAction("Add Switch")
        modify_menu = menu.addMenu("Modify")
        modify_name_action = modify_menu.addAction("Modify device name")
        modify_ip_action = modify_menu.addAction("Modify IP address/subnet mask")
        modify_vlan_action = modify_menu.addAction("Modify VLANs")

        shutdown = menu.addAction("Remove Device")


        action = menu.exec_(self.mapToGlobal(pos()))  # where the menu pops up
        if action == info_action:
            self.__display_info(controller_obj, self.mapToGlobal(pos()))
        elif action == modify_name_action:
            self.__modify_name(controller_obj, self.mapToGlobal(pos()))
        elif action == modify_ip_action:
            self.__modify_ip_address(controller_obj, self.mapToGlobal(pos()))
        elif action == modify_vlan_action:
            self.__modify_vlan(controller_obj, self.mapToGlobal(pos()))
        elif action == add_switch_action:
            self.add_switch(controller_obj)

        elif action == shutdown:
            if controller_obj.has_children():
                error_message("Cannot remove controller",
                              "This controller still has children connected",
                              "Remove children first to proceed")
            else:
                self.__shutdown_device(controller_obj)

                # Context menu for controller

    '''Private context menu for switch'''
    def __switch_menu(self, pos, switch_obj):

        menu = QMenu(self)
        info_action = menu.addAction("Display Info")
        add_menu = menu.addMenu('Add')
        add_switch_action = add_menu.addAction("Add Switch")
        add_host_action = add_menu.addAction("Add Host")
        add_multiple_hosts_action = add_menu.addAction("Add Multiple Hosts")
        add_connection_action = add_menu.addAction("Add Connection")
        modify_menu = menu.addMenu("Modify")
        modify_name_action = modify_menu.addAction("Modify device name")
        modify_ip_action = modify_menu.addAction("Modify IP Address/Subnet Mask")
        modify_vlan_action = modify_menu.addAction("Modify VLANs")
        shutdown = menu.addAction("Remove Device")



        action = menu.exec_(self.mapToGlobal(pos()))  # where the menu pops up
        if action == info_action:
            self.__display_info(switch_obj, self.mapToGlobal(pos()))
        elif action == add_switch_action:        # this action adds a switch as a child if there is screen space left
            if switch_obj.row > (ALLOWABLE_ROWS-3):
                error_message("You cannot add any more devices to this switch",
                         "This program only supports depth of 10",
                         "You can change this in the source code if you really need too")
            else:
                self.add_switch(switch_obj)
        elif action == add_host_action:          # this action is to add a host as a child of that switch
            self.add_host(switch_obj)
            self.__update_entire_gui()
        elif action == add_multiple_hosts_action:          # this action is to add a host as a child of that switch
            self.__add_multiple_hosts(switch_obj, self.mapToGlobal(pos()))
        elif action == add_connection_action:    # this action is setting up the screen for connection selection
            self.add_connection_switch = switch_obj
            self.add_connection_bool = True
            QApplication.setOverrideCursor(Qt.WhatsThisCursor)
            self.statusbar.showMessage("Left Click Device to Connect Too")
            self.update()
        elif action == modify_name_action:
            self.__modify_name(switch_obj, self.mapToGlobal(pos()))
        elif action == modify_ip_action:
            self.__modify_ip_address(switch_obj, self.mapToGlobal(pos()))
        elif action == modify_vlan_action:
            self.__modify_vlan(switch_obj, self.mapToGlobal(pos()))
        elif action == shutdown:          # this action is to shutdown the switch only if it has no direct children
            if switch_obj.has_children():
                error_message("Cannot remove switch",
                         "This switch still has children connected",
                         "remove children first to proceed")
            else:
                self.__shutdown_device(switch_obj)

    '''Private context menu for host'''
    def __host_menu(self, pos, host_obj):

        menu = QMenu(self)
        info_action = menu.addAction("Display Info")
        modify_menu = menu.addMenu("Modify")
        modify_name_action = modify_menu.addAction("Modify device name")
        modify_ip_action = modify_menu.addAction("Modify IP Address/Subnet Mask")
        modify_vlan_action = modify_menu.addAction("Modify VLAN")
        shutdown = menu.addAction("Remove Device")


        action = menu.exec_(self.mapToGlobal(pos()))  # where the menu pops up
        if action == info_action:
            self.__display_info(host_obj, self.mapToGlobal(pos()))
        elif action == modify_name_action:
            self.__modify_name(host_obj, self.mapToGlobal(pos()))
        elif action == modify_ip_action:
            self.__modify_ip_address(host_obj, self.mapToGlobal(pos()))
        elif action == modify_vlan_action:
            self.__modify_vlan(host_obj, self.mapToGlobal(pos()))
        elif action == shutdown:
            self.__shutdown_device(host_obj)

    '''Listener for mouse click events overloading PyQt base function gets called automatically'''
    def mousePressEvent(self, event):

        child = self.childAt(event.pos())   #selects the object being clicked on
        if not child:                       #if not a clickable object get out
            return

        objectType = "" #check what type of device is being clicked on
        child_id = id(child)

        for i in self.controller_list:           #check controller_list
            if (child_id == id(i.icon)):
                objectType = "controller"
                network_object = i

        if objectType == "":
            for i in self.switch_list:           #check switch_list
                if (child_id == id(i.icon)):
                    objectType = "switch"
                    network_object = i

        if objectType == "":                    #check host_list
            for i in self.host_list:
                if (child_id == id(i.icon)):
                    objectType = "host"
                    network_object = i

        if objectType == "":                    #default
            return

        #Right mouse button click action
        if event.buttons() == Qt.RightButton:
            self.add_connection_bool = False    # if a user decides not to add a connection
            self.add_connection_switch = None   # if a user decides not to add a connection
            QApplication.setOverrideCursor(Qt.ArrowCursor)  # if a user decides not to add a connection

            if objectType == "controller": self.__controller_menu(event.pos, network_object)
            if objectType == "switch": self.__switch_menu(event.pos, network_object)
            if objectType == "host": self.__host_menu(event.pos, network_object)

        # left mouse button click action
        elif event.buttons() == Qt.LeftButton:
            #the following is a branch option if the user is trying to add a switch connection
            if self.add_connection_bool:
                self.add_connection_bool = False    # reset gate
                QApplication.setOverrideCursor(Qt.ArrowCursor)  # change back mouse indicator
                if self.add_connection_switch == network_object:
                    error_message("Cannot add connection to self")
                else:
                    self.add_connection(self.add_connection_switch, network_object, event.pos)
            return

    '''Static function for popup menu to show the info on each device'''
    @staticmethod
    def __display_info(net_device, pos):

        display_string = ""
        display_string += "Type:        " + net_device.type + "\n"
        display_string += "Name:        " + net_device.display_id + "\n"
        display_string += "IP Addr:     " + net_device.ip_address + "\n"
        display_string += "Subnet Mask: " + net_device.netmask + "\n"
        display_string += "MAC Addr:    " + net_device.mac_address + "\n"

        if net_device.type == "Host":
            display_string += "Native_VLAN:    " + str(net_device.vlan) + "\n"
        else:
            vlan_string = ""
            vlans_sorted = sorted(net_device.vlans)
            for vlan in vlans_sorted:
                vlan_string += str(vlan) + ", "
            display_string += "Tagged_VLANs:    " + vlan_string.rstrip(", ") + "\n"

            if net_device.type == "Switch":
                display_string += "DPID:    " + net_device.dp_id + "\n"
                controller_string = "Assigned Controllers: "
                for i in net_device.controller_list:
                    controller_string += i.id + ", "
                display_string += controller_string.rstrip(", ") + "\n"

        info_message(display_string, pos)

    '''Private function to change the boolean and update the painter'''
    def __config_labels(self):

        if self.show_labels_bool: self.show_labels_bool = False
        else: self.show_labels_bool = True
        self.__refresh_pixmaps()
        self.statusbar.showMessage("Configured Labels")
        self.update()

    '''Private function to save current controller configuration to YAML'''
    def __save_controller_yaml(self):
        dropdown_items = []
        for control in self.controller_list:
            dropdown_items.append(control.id)

        if dropdown_items.__len__() == 0:
            error_message("No Controllers to save configuration of")
            return

        selection, ok = QInputDialog.getItem(self,
                                             "select input dialog",
                                             "list of controllers",
                                             dropdown_items, 0, False)
        if ok and selection:
            file_name = QFileDialog.getSaveFileNameAndFilter(self, 'Save YAML File','',"YAML (*.yaml)")
            if not file_name[0].isEmpty():  # ensure user did not cancel out of file selection
                for control in self.controller_list:
                    if selection == control.id:
                        self.yaml.write_to_file(control, file_name[0].split(".yaml")[0]+".yaml")
                        self.statusbar.showMessage("File Saved")

    '''Private function to save current configuration in a .conf file'''
    def __save_configuration(self):
        if not self.controller_list:
            error_message("Nothing to save configuration of")
            return

        file_name = QFileDialog.getSaveFileNameAndFilter(self, 'Save Configuration File', '', "VIRTNET (*.virtnet)")
        if not file_name[0].isEmpty():  # checking the first qstring of the tuple returned by above function for empty
            self.conf.write(file_name[0].split(".virtnet")[0]+".virtnet", self.controller_list, self.switch_list)
            self.statusbar.showMessage("File Saved")

    '''Private function to load configuration from a .conf file '''
    def __load_configuration(self):

        file_name = QFileDialog.getOpenFileNameAndFilter(self, 'Open Configuration File', '', "VIRTNET (*.virtnet)")
        if not file_name[0].isEmpty(): # checking the first qstring of the tuple returned by above function for empty
            if self.controller_list:  # going to wipe the network before loading anything
                self.__wipe_network() # first, clear old network and shutdown devices


            self.loading_mode_bool = True
            self.conf.read(file_name[0], self) # second, read in new network configurations
            self.statusbar.showMessage("File Opened")  # when complete, show message at bottom of screen


            self.loading_mode_bool = False
            self.__update_entire_gui()  # update the new graphical representation of the network

    '''Static function for pop-up radio box to select connection type'''
    @staticmethod
    def __connection_radio_message(pos):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)

        msg.setText("Select Connection Type")
        msg.setWindowTitle("Device Connection Options")
        msg.addButton(QMessageBox.Yes).setText("in-band")
        msg.addButton(QMessageBox.No).setText("out-of-band")
        msg.addButton(QMessageBox.Cancel).setText("both")

        msg.move(pos)
        result = msg.exec_()
        if result == QMessageBox.Yes:
            return "in_band"
        elif result == QMessageBox.No:
            return "out_band"
        elif result == QMessageBox.Cancel:
            return "both_band"

    '''Private function to launch menu to modify VLAN data'''
    def __modify_vlan(self, device, pos):
        msg = QMessageBox()
        msg.move(pos)
        msg.setStandardButtons(QMessageBox.Apply | QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Apply)
        layout = msg.layout()

        '''The following adds display and input elements to the modification box lots of 
        magic numbers becuase there was no simpler or cleaner way to do this with the addWidget 
        function and still have the elements show side by side'''
        msg.setWindowTitle("Device VLAN Modification")
        layout.addWidget(QLabel("Please make changes and then select apply", msg), 0, 0, 1, 2)
        layout.addWidget(QLabel("-"*50, msg), 1, 0, 1, 2)
        layout.addWidget(QLabel("", msg))  # spacing because I cant move the apply button

        '''If this is a switch/host we may want to propagate the new VLAN data up the network'''
        propagate_check = QCheckBox("Propagate to parent devices?")
        if device.type != "Controller":
            layout.addWidget(propagate_check)

        vlan_edit = QLineEdit()
        if device.type == "Host":
            vlan_edit.setText(str(device.vlan))
            layout.addWidget(QLabel("VLAN", msg), 6, 0)
            layout.addWidget(vlan_edit, 6, 1)
        else:  # device is either switch or controller
            vlan_string = ""
            for i in device.vlans:
                vlan_string += str(i) + " "
            vlan_edit = QLineEdit(vlan_string)
            layout.addWidget(QLabel("VLAN LIST", msg), 6, 0)
            layout.addWidget(vlan_edit, 6, 1)

        result = msg.exec_()  # launch modification menu

        '''Now we look to use the results'''
        if result == QMessageBox.Apply:
            t_vlan = str(vlan_edit.text())  # convert from QString to regular String
            if device.type == "Host":
                try:  # checking vlan validity
                    if t_vlan.strip() == '': raise ValueError("Host V_LAN cannot be empty:\n")
                    if (t_vlan.split()).__len__() > 1: raise ValueError("Host V_LAN can only have 1 VLAN")
                    device.vlan = t_vlan.strip()
                    if propagate_check.checkState():
                        self.__add_v_lan(device.parent, device.vlan)
                except ValueError as err:
                    error_message("Invalid V_LAN "+err[0])
            else:  # device is either switch or controller
                try:
                    vlan_list = str(vlan_edit.text()).split()
                    device.vlans.clear() # clear the current vlan list
                    for i in vlan_list:  # populate the vlan list with manual entries
                        if device.type == "Switch" and propagate_check.checkState():
                            self.__add_v_lan(device, i.strip())  # recursive propagation of vlan
                        else:
                            device.vlans.add(i.strip())
                except:
                    error_message("Invalid V_LAN Data")

    '''Private function to launch menu to modify the device IP address'''
    def __modify_ip_address(self, device, pos):
        msg = QMessageBox()
        msg.move(pos)
        msg.setStandardButtons(QMessageBox.Cancel | QMessageBox.Apply)
        msg.setDefaultButton(QMessageBox.Apply)
        layout = msg.layout()

        '''The following adds display and input elements to the modification box lots of 
        magic numbers because there was no simpler or cleaner way to do this with the addWidget 
        function and still have the elements show side by side'''
        msg.setWindowTitle("Device IP Modification")
        layout.addWidget(QLabel("Please make changes and then select apply", msg), 0, 0, 1, 2)
        layout.addWidget(QLabel("-" * 50, msg), 1, 0, 1, 2)
        layout.addWidget(QLabel("", msg))  # spacing because I cant move the apply button

        ip_edit = QLineEdit()
        ip_edit.setText(device.ip_address)
        layout.addWidget(QLabel("IP_ADDR", msg), 3, 0)
        layout.addWidget(ip_edit, 3, 1)

        netmask_edit = QLineEdit()
        netmask_edit.setText(device.netmask)
        layout.addWidget(QLabel("NET_MASK", msg), 4, 0)
        layout.addWidget(netmask_edit, 4, 1)

        result = msg.exec_()  # launch modification menu

        '''Now we look to use the results'''
        if result == QMessageBox.Apply:
            try:  # checking IP Address validity
                socket.inet_aton(str(ip_edit.text()))
                device.ip_address = str(ip_edit.text())
            except:
                error_message("Invalid IP Address")
            try:  # checking Netmask validity
                socket.inet_aton(str(netmask_edit.text()))
                device.netmask = str(netmask_edit.text())
            except:
                error_message("Invalid Subnet Mask Address")

    '''Private function to launch menu to modify the device display name'''
    def __modify_name(self, device, pos):
        msg = QMessageBox()
        msg.move(pos)
        msg.setStandardButtons(QMessageBox.Cancel | QMessageBox.Apply)
        msg.setDefaultButton(QMessageBox.Apply)
        layout = msg.layout()

        '''The following adds display and input elements to the modification box lots of 
        magic numbers because there was no simpler or cleaner way to do this with the addWidget 
        function and still have the elements show side by side'''
        msg.setWindowTitle("Device Name Modification")
        layout.addWidget(QLabel("Please make changes and then select apply", msg), 0, 0, 1, 2)
        layout.addWidget(QLabel("-" * 50, msg), 1, 0, 1, 2)
        layout.addWidget(QLabel("", msg))  # spacing because I cant move the apply button

        name_edit = QLineEdit()
        name_edit.setText(device.display_id)
        layout.addWidget(QLabel("NAME:", msg), 3, 0)
        layout.addWidget(name_edit, 3, 1)

        result = msg.exec_()  # launch modification menu

        '''Now we look to use the results'''
        if result == QMessageBox.Apply:
            try:  # new name validity checks would go here
                device.display_id = str(name_edit.text())
            except:
                error_message("Display Name")

            self.__update_entire_gui()  # since the name has been changed on the screen

    '''Private function to generate and display a report on what hosts are in which vlans'''
    def __vlan_report(self):
        dialog = QDialog(self.central_widget)  #creates a pop-up report
        dialog.setWindowTitle("VLAN Report")  #set title
        layout = QVBoxLayout()  #need to create a layout so tree view gets properly displayed
        dialog.setLayout(layout)  # set the layout to the dialog box
        tree = QTreeView()  #this is a QWidget used for displaying relational data
        layout.addWidget(tree)  #adding our tree to the general layout
        model = QStandardItemModel()  #this is how the data is stored for the tree view
        tree.setModel(model)   #of course we then need to associate the data with the tree

        cat_headers = ['VLAN [hostname]', "IP_Address", "DPID"]
        model.setHorizontalHeaderLabels(cat_headers)

        rootNode = model.invisibleRootItem()
        vlan_data = {}  # a dictionary to keep track of vlans
        for i in self.host_list:  # The first time this is looping through to just find unique VLANS
            if i.vlan not in vlan_data:
                vlan_data[i.vlan] = QStandardItem(str(i.vlan))
                rootNode.appendRow(vlan_data[i.vlan])

        for i in self.host_list:  # The second time this is looping through to add to the data structure
            node = (QStandardItem(str(i.id)), QStandardItem(str(i.ip_address)), QStandardItem(str(i.mac_address)))
            vlan_data[i.vlan].appendRow(node)

        tree.sortByColumn(0, Qt.AscendingOrder)  # sort the vlans
        tree.expandAll()  # default to expanded view

        dialog.setWindowModality(Qt.NonModal) # A nonmodal window does not block input to other windows
        dialog.show()

    '''Private function to allow user to select a color for the background'''
    def __color_selector(self):
        color_dialog = QColorDialog()  # creates a pop-up menu for color selection
        color_dialog.setWindowTitle("Color Selector Menu")  # set title
        color_dialog.exec_()    #execute dialog
        self.central_widget.set_background_color(color_dialog.currentColor())  # set the color to what was chosen

    '''Private function to cleanly shut down a single network device'''
    def __shutdown_device(self, net_device):
        if net_device.type == "Host" or net_device.type == "Switch":
            net_device.parent.remove_child(net_device)

        '''clear out any additional connections from other devices'''
        if net_device.type == "Switch" or net_device.type == "Controller":
            for i in self.switch_list:
                i.remove_child(net_device)


        net_device.shutdown()

        layout = self.row_list[net_device.row]
        for i in reversed(range(layout.count())):
            widgetToCheck = layout.itemAt(i).widget()
            if net_device.icon_id == id(widgetToCheck):
                layout.removeWidget(widgetToCheck)  # remove it from the layout list
                widgetToCheck.setParent(None)  # remove it from the gui

        '''the following goes through and cleans up the sdnwidget instantiations'''
        if net_device.type == "Host":
            self.host_list.remove(net_device)
        if net_device.type == "Switch":
            self.switch_list.remove(net_device)
        elif net_device.type == "Controller":
            self.controller_list.remove(net_device)

        self.statusbar.showMessage("Removed Device")
        self.__update_entire_gui()

    '''Private function to delete everything on the network and reset parameters'''
    def __wipe_network(self):

        '''Removing instances of each of these devices'''
        self.host_list[:] = []
        self.switch_list[:] = []
        self.controller_list[:] = []


        '''Removing all GUI network device icons'''
        for i in self.row_list:
            for j in reversed(range(i.count())):
                widgetToRemove = i.itemAt(j).widget()
                i.removeWidget(widgetToRemove)  # remove it from the layout list
                widgetToRemove.setParent(None) # remove it from the gui
        self.__update_entire_gui()

        '''Setting init variables back to default'''
        self.controller_id_number = 1
        self.central_widget.paint_lines_bool = True

        self.statusbar.showMessage("Everything Cleared")

    '''Public function to ensure when the program is closed that the network gets taken down'''
    def closeEvent(self, QCloseEvent):
        self.__wipe_network()


'''--------------------------GLOBAL FUNCTIONS AND MAIN------------------------------------------------'''


'''GLOBAL Function for pop-up error boxes'''
def error_message(error_string, detail_string="", fix_string=""):

    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setText(error_string)
    msg.setFont(QFont("courier", 10))
    msg.setInformativeText(detail_string)
    msg.setWindowTitle("Error Message")
    msg.setDetailedText(fix_string)
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()


'''GLOBAL Function for pop-up information boxes'''
def info_message(info_string, pos):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setFont(QFont("courier", 10))
    msg.setText(info_string)
    msg.setWindowTitle("Device Information")
    msg.setStandardButtons(QMessageBox.Ok)
    msg.move(pos)
    msg.exec_()


'''MAIN'''
def main():
    app = QApplication(sys.argv)
    sdn = SdnWidget()
    sdn.show()
    sys.exit(app.exec_())


'''supplemental for main'''
if __name__ == '__main__':              # if we're running file directly and not importing it
    main()                              # run the main function

