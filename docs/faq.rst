.. meta::
   :keywords: Openflow, Ryu, Faucet, VLAN, SDN

==========
Faucet FAQ
==========

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
What are the multi-table requirements for Faucet? Should the table number start from Zero (0) or can it start at arbitrary location (say, 100)?  For example, in HP OF switches, you don't have to store anything in table 0.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
The initial table is configurable using a table offset value in the config -- *Which config file?*

----------------------------------------------------------------------------------------------------------------------------------------------------
Some controllers / applications do not learn traffic from / to local. This prevents any inband management from succeeding. What does Faucet do here?
----------------------------------------------------------------------------------------------------------------------------------------------------
I would have to double check, but you could set up your in-band management separately and Faucet will not interfere with it Eth/VLAN/IP match forwarding.

----------------------------------------------------------------------------
Does Faucet support pushing flow with Eth/VLAN/IP match with ethertype 8100?
----------------------------------------------------------------------------
Faucet uses 8100 as the TPID

-------------------------------------------------------------------------------------
How are packet-ins handled when a message is generated through table-miss flow entry?
-------------------------------------------------------------------------------------
Faucet adds explicit rules for unmatched packets.

--------------------------------------
Are group actions supported in Faucet?
--------------------------------------
No.
---------------------------------------------------------------------------------
Does Faucet send any multi-part requests?  If so, please provide sample use cases
---------------------------------------------------------------------------------
Gauge uses multi-part messages for the stats collection (flow table stats and port stats).

----------------------------------------------
How does Faucet handle unsupported OF version?
----------------------------------------------
Not sure.

-------------------------------------
Does Faucet install table-miss entry?
-------------------------------------
Yes.

-------------------------------------------------------------
Does Faucet clear all all switch table entries on connection?
-------------------------------------------------------------
Faucet gives all entries a specific cookie, and it clears all entries with that cookie. I.e., it clears entries added by itself but not anyone else.

-------------------------------------------------------------------------------
Does Faucet install fresh set of table entries on connection and re-connection?
-------------------------------------------------------------------------------
Yes.

------------------------------------------------------
Can Faucet connect to a switch running in hybrid mode?
------------------------------------------------------
Not tested.

--------------------------------------------------------------------------------------------------------------------
Does Faucet installed flows support priority?  How is this defined - who get higher priority than the other and why?
--------------------------------------------------------------------------------------------------------------------
Yes, priority is necessary for a number of things. Example: there are higher priority rules for packets with a known source address, and lower ones to send those packets to the controller.

------------------------------------------
Is there a gui for generating a YAML file?
------------------------------------------
No.

-------------------------------------
Can we provide some documentation on:
-------------------------------------
* **how a switch vendor needs to provide a YAML file;**
* **how a deployer can check and use a YAML file to suit his network;**
* **how should a network be designed and deployed (a sample OF network for office)?**

Yes, *but Brad and I are discussing changing the configuration significantly soon so I am not eager to document it too much at the moment.*

-------------------------------------------------------------------------------------------------------------------------------------
Should Faucet detect Management, OF controller ports and gateway ports on the switch or pure OF only ports where hosts are connected?
-------------------------------------------------------------------------------------------------------------------------------------
Out of scope for Faucet as it is currently.

-----------------------------------------------------------------------------------------------
If another controller is connected to the switch in addition to Faucet, what happens to Faucet?
-----------------------------------------------------------------------------------------------
Faucet identifies its own flows using a cookie value, if the other controller doesn’t use the same cookie value there shouldn’t be a problem (provided the rules don’t conflict in a problematic way)

--------------------------------------------------------------------------------------------------------------------
If another controller connected to switch changes role (master, slave, equal) on the switch, what happens to Faucet?
--------------------------------------------------------------------------------------------------------------------
Shouldn’t be an issue, if another controller is the master then my understanding is Faucet wouldnt be able to install any flows however?

--------------------------------------------
How does the L2 Mac learning algorithm work?
--------------------------------------------
When the controller sees a new mac (on a per VLAN basis) it deletes any existing rules for that mac that may exist on that vlan (the controller does not keep a record of them) and installs new ones.

------------------------------
Does Faucet send LLDP packets?
------------------------------
No.

------------------------------------------------------------------------------------------------------
Some switches always send VLAN info in packet_in messages and some don't. How does Faucet handle this?
------------------------------------------------------------------------------------------------------
Packets should have VLANs pushed before being sent to the controller.

----------------------------------------------------------------------------
Is there a event handler registered to detect if flows on the switch change?
----------------------------------------------------------------------------
No.

--------------------------------------
Does Faucet use auxiliary connections?
--------------------------------------
No.

--------------------------------------
Does Faucet support L2.5 (MPLS, etc.)?
--------------------------------------
No.

---------------------------------------------------
Stats - what does Faucet collect (flow count, etc)?
---------------------------------------------------
Gauge collects port stats and takes a full flow-table dump periodically.

-------------------
How do I use Gauge?
-------------------
Give Gauge a list of Faucet yaml config files and it will poll them for stats (as specified in the config file).

--------------------------------------------------
Does Faucet use cookie info in packet_in messages?
--------------------------------------------------
I don't remember if it checks cookies on packet ins. It probably should.
