

.. code-block:: html
<pre>
What are the multi-table requirements for faucet?
Should the table number start from Zero (0) or can it start at arbitrary location (say, 100)?  For example, in HP OF switches, you don't have to store anything in table 0. — The initial table is configurable using a table offset value in the config (Which config file?)
Learning Port local:
Some controllers / applications do not learn traffic from / to local. This prevents any inband management from succeeding. What does faucet do here? I would have to double check, but you could set up your in-band management separately and faucet will not interfere with it
Eth/VLAN/IP match forwarding
Does faucet support pushing flow with Eth/VLAN/IP match with ethertype 8100
Faucet uses 8100 as the TPID
Packet-in
How are packet-ins handled when a message is generated through table-miss flow entry?
Faucet adds explicit rules for unmatched packets
Group actions are not supported in Faucet - Correct
Does faucet send any multi-part requests?  If so, please provide sample use cases -  Gauge uses multi-part messages for the stats collection (flow table stats and port stats)
How does faucet handle unsupported OF version? — Not sure
Does faucet install table-miss entry? — Yes
Does faucet clear all all switch table entries on connection? —  Faucet gives all entries a specific cookie, and it clears all entries with that cookie. I.e., it clears entries added by itself but not anyone else.
Does faucet install fresh set of table entries on connection and re-connection? — Yes
Can faucet connect to a switch running in hybrid mode?  — Not tested
Does faucet installed flows support priority?  How is this defined - who get higher priority than the other and why? — Yes, priority is necessary for a number of things. Example: there are higher priority rules for packets with a known source address, and lower ones to send those packets to the controller.
Is there a gui for generating a YAML file? — No
Can we provide some documentation on: (Yes, but Brad and I are discussing changing the configuration significantly soon so I am not eager to document it too much at the moment.)
how a switch vendor needs to provide a YAML file?
how a deployer can check and use a YAML file to suit his network?
how should a network be designed and deployed - a sample OF network for office
Should faucet detect Management, OF controller ports and gateway ports on the switch or pure OF only ports where hosts are connected? — out of scope for faucet as it is currently
If another controller is connected to the switch in addition to Faucet, what happens to faucet? — Faucet identifies its own flows using a cookie value, if the other controller doesn’t use the same cookie value there shouldn’t be a problem (provided the rules don’t conflict in a problematic way)
If another controller connected to switch changes role (master, slave, equal) on the switch, what happens to faucet? Shouldn’t be an issue, if another controller is the master then my understanding is faucet wouldnt be able to install any flows however?
Describe L2 Mac learning algorithm used — When the controller sees a new mac (on a per vlan basis) it deletes any existing rules for that mac that may exist on that vlan (the controller does not keep a record of them) and installs new ones. See also this comment: https://github.com/REANNZ/faucet/blob/master/valve.py#L512 It explains the timeout.
Does faucet send LLDP packets? — No
Some switches always send VLAN info in packet_in messages and some don't.  How does faucet handle this? — Packets should have vlans pushed before being sent to the controller.
Is there a event handler registered to detect if flows on the switch change? — No
Does faucet use auxiliary connections? — No
Does faucet support L2.5 - MPLS, etc — No
Stats - what does faucet collect - flow count, etc — Gauge collects port stats and takes a full flow-table dump periodically
How to use Gauge? — give Gauge a list of faucet yaml config files and it will poll them for stats (as specified in the config file)
Does faucet use cookie info in packet_in messages - answer for both yes and no — I dont remember if it checks cookies on packet ins. It probably should.


</pre>
