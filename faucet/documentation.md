

# **DP**

| Attribute | Default | Description |
| --------- | ------- | ----------- |
| arp_neighbor_timeout | 500|    ARP and neighbor timeout (seconds) | 
| cookie | 1524372928|    Identification cookie value to allow for multiple controllers to control the same datapath | 
| description | None|    description, strictly informational | 
| dp_id | None|    Name for this dp, used for stats reporting and configuration | 
| drop_bpdu | True|    By default drop STP BPDU frames | 
| drop_broadcast_source_address | True|    By default drop packets with a broadcast source address | 
| drop_lldp | True|    By default, drop LLDP. Set to False, to enable NFV offload of LLDP. | 
| drop_spoofed_faucet_mac | True|    By default drop packets on datapath spoofing the FAUCET_MAC | 
| eth_dst_table | None|   | 
| eth_src_table | None|   | 
| flood_table | None|    How much to offset default priority by | 
| group_table | False|    Use GROUP tables for IP routing and vlan flooding | 
| hardware | Open vSwitch|   | 
| high_priority | None|   | 
| highest_priority | None|   | 
| ignore_learn_ins | 3|    Ignore every approx nth packet for learning. 2 will ignore 1 out of 2 packets; 3 will ignore 1 out of 3 packets. | 
| interfaces | {}|   | 
| ipv4_fib_table | None|   | 
| ipv6_fib_table | None|   | 
| learn_ban_timeout | 10|    When banning/limiting learning, wait this many seconds before learning can be retried | 
| learn_jitter | 10|    Jitter learn timeouts by up to this many seconds | 
| low_priority | None|   | 
| lowest_priority | None|   | 
| max_host_fib_retry_count | 10|    Max number of times to retry resolution of a host FIB route. | 
| max_hosts_per_resolve_cycle | 5|    Max hosts to try to resolve per gateway resolution cycle. | 
| max_resolve_backoff_time | 32|    Max number of seconds to back off to when resolving nexthops. | 
| name | None|   | 
| ofchannel_log | None|    OF channel log | 
| packetin_pps | 0|    Ask switch to rate limit packet pps. TODO: Not supported by OVS in 2.7.0 | 
| port_acl_table | None|    The table for internally associating vlans | 
| priority_offset | 0|    Some priority values | 
| stack | None|    stacking config, when cross connecting multiple DPs | 
| table_offset | 0|   | 
| timeout | 300|    inactive MAC timeout | 
| vlan_acl_table | None|   | 
| vlan_table | None|   | 


# **Port**

| Attribute | Default | Description |
| --------- | ------- | ----------- |
| acl_in | None|   | 
| description | None|   | 
| enabled | True|   | 
| max_hosts | 255|   maximum number of hosts | 
| mirror | None|   | 
| mirror_destination | False|   | 
| name | None|   | 
| native_vlan | None|   | 
| number | None|   | 
| permanent_learn | False|   | 
| stack | None|   | 
| tagged_vlans | None|   | 
| unicast_flood | True|   | 


# **Router**

| Attribute | Default | Description |
| --------- | ------- | ----------- |
| vlans | None|   | 


# **VLAN**

| Attribute | Default | Description |
| --------- | ------- | ----------- |
| acl_in | None|   | 
| bgp_as | 0|   | 
| bgp_local_address | None|   | 
| bgp_neighbor_addresses | []|   | 
| bgp_neighbor_as | None|   | 
| bgp_neighbour_addresses | []|   | 
| bgp_neighbour_as | 0|   | 
| bgp_port | 9179|   | 
| bgp_routerid | |   | 
| description | None|   | 
| faucet_vips | None|   | 
| max_hosts | 255|    Limit number of hosts that can be learned on a VLAN. | 
| name | None|   | 
| proactive_arp_limit | None|    Don't proactively ARP for hosts if over this limit (None unlimited) | 
| proactive_nd_limit | None|    Don't proactively ND for hosts if over this limit (None unlimited) | 
| routes | None|   | 
| unicast_flood | True|   | 
| vid | None|   | 
