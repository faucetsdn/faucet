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

class ValveTableConfig: # pylint: disable=too-few-public-methods
    """Configuration for a single table."""

    def __init__(self, name, match_types, exact_match):
        self.name = name
        self.match_types = match_types
        self.exact_match = exact_match


FAUCET_PIPELINE = (
    ValveTableConfig('port_acl', None, None),
    ValveTableConfig(
        'vlan',
        (('eth_dst', True), ('eth_type', False),
         ('in_port', False), ('vlan_vid', False)),
        False),
    ValveTableConfig('vlan_acl', None, None),
    ValveTableConfig(
        'eth_src',
        (('eth_dst', True), ('eth_src', False), ('eth_type', False),
         ('in_port', False), ('vlan_vid', False)),
        False),
    ValveTableConfig(
        'ipv4_fib',
        (('eth_type', False), ('ipv4_dst', True), ('vlan_vid', False)),
        False),
    ValveTableConfig(
        'ipv6_fib',
        (('eth_type', False), ('ipv6_dst', True), ('vlan_vid', False)),
        False),
    ValveTableConfig(
        'vip',
        (('arp_tpa', False), ('eth_dst', False), ('eth_type', False),
         ('icmpv6_type', False), ('ip_proto', False)),
        False),
    ValveTableConfig(
        'eth_dst',
        (('eth_dst', False), ('in_port', False), ('vlan_vid', False)),
        False),
    ValveTableConfig(
        'flood',
        (('eth_dst', True), ('in_port', False), ('vlan_vid', False)),
        False),
)
