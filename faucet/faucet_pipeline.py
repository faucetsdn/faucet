"""Standard FAUCET pipeline."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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
# The second item in the tuple, is a list of tuples of OpenFlow matches
# that the table uses, and a flag whether the field is masked.

FAUCET_PIPELINE = (
    ('port_acl', None),
    ('vlan',
     (('eth_dst', True), ('eth_type', False),
      ('in_port', False), ('vlan_vid', False))),
    ('vlan_acl', None),
    ('eth_src',
     (('eth_dst', True), ('eth_src', False), ('eth_type', False),
      ('in_port', False), ('vlan_vid', False))),
    ('ipv4_fib',
     (('eth_type', False), ('ipv4_dst', True), ('vlan_vid', False))),
    ('ipv6_fib',
     (('eth_type', False), ('ipv6_dst', True), ('vlan_vid', False))),
    ('vip',
     (('arp_tpa', False), ('eth_dst', False), ('eth_type', False),
      ('icmpv6_type', False), ('ip_proto', False))),
    ('eth_dst',
     (('eth_dst', False), ('in_port', False), ('vlan_vid', False))),
    ('flood',
     (('eth_dst', True), ('in_port', False), ('vlan_vid', False))),
)
