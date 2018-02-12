"""Standard FAUCET pipeline."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# pipeline definition is a list of tuples, one tuple per table,
# starting at OpenFlow table 0.
# The first item in tuple is the table name.
# The second item in the tuple is a tuple of OpenFlow matches, that table ues.
FAUCET_PIPELINE = (
    ('port_acl', None),
    ('vlan', ('eth_dst', 'eth_type', 'in_port', 'vlan_vid')),
    ('vlan_acl', None),
    ('eth_src', ('eth_dst', 'eth_src', 'eth_type', 'in_port', 'vlan_vid')),
    ('ipv4_fib', ('eth_type', 'ipv4_dst', 'vlan_vid')),
    ('ipv6_fib', ('eth_type', 'ipv6_dst', 'vlan_vid')),
    ('vip', ('arp_tpa', 'eth_dst', 'eth_type', 'icmpv6_type', 'ip_proto')),
    ('eth_dst', ('eth_dst', 'in_port', 'vlan_vid')),
    ('flood', ('eth_dst', 'in_port', 'vlan_vid')))
