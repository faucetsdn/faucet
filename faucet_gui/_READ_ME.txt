_  _ _ ____ ___ _  _ ____ ___    ____ ____ ____ ____ ___ ____ ____
|  | | |__/  |  |\ | |___  |     |    |__/ |___ |__|  |  |  | |__/
 \/  | |  \  |  | \| |___  |     |___ |  \ |___ |  |  |  |__| |  \



MOTIVATION:
  To create a simple GUI based network designer that could quickly generate YAML files for a Faucet SDN controller.


FEATURES:
	Allows SDN network diagram building without having an in-depth knowledge of networking.
	Acts as a GUI based tool to create and save off YAML files for Faucet (an open source SDN controller app)
        Add multiple switches, hosts, controllers and have them be connected
        Save and Load network configurations for use later or sharing network topologies
	
	Automatically provisions in/out of band networking for control and data planes
        Change IP/Subnet/Mac/Vlan using the gui
        Add additional in/out of band connections between switches
	

INSTALLATION:
  A.  Need to have Python 2.7 and PyQt4 Libraries installed.


RUNNING:
  A. Run the main.py file and everything else will work


HOW TO USE:
  A.  Once you start the program you can add devices (Controllers, Switches, Hosts) one at a time by right clicking on
  the top level controller and selecting the add device button.  From here you can add as many devices as you desire by
  right clicking on any of the devices on screen and selecting from the add menu.  On each device you can then modify
  things like (IP/Netmask/MAC/VLAN) by right clicking on the object then selecting from the modify options.  Once the
  network is created and modified you can safe the work in a format specific to this program by selecting save from
  the top bar menu on the program main window.  You could also load configurations at any time in a similar way.
  Most importantly you can save off a YAML description of the current network that is meant to work with Faucet.


CODE STYLE:
	Python PEP-8


Credits:
  Thanks to Faucet, and PyQt.
  Thanks to the technical adviser on the project Brett Sovereign

  This code was written by Brendan Geoghegan
  

License:
  Apache 2

