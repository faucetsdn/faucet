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

    def __init__(self, name, exact_match=None, match_types=None, set_fields=None):
        self.name = name
        self.exact_match = exact_match
        self.match_types = match_types
        self.set_fields = set_fields

    def __str__(self):
        return 'table config: %s exact match: %s match types: %s set_fields: %s' % (
            self.name, self.exact_match, self.match_types, self.set_fields)

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __lt__(self, other):
        return self.__hash__() < other.__hash__()


FAUCET_PIPELINE = (
    ValveTableConfig(
        'port_acl'),
    ValveTableConfig(
        'vlan', False,
        (('eth_dst', True), ('eth_type', False),
         ('in_port', False), ('vlan_vid', False)),
        ('vlan_vid',)),
    ValveTableConfig(
        'vlan_acl'),
    ValveTableConfig(
        'eth_src', False,
        (('eth_dst', True), ('eth_src', False), ('eth_type', False),
         ('in_port', False), ('vlan_vid', False)),
        None),
    ValveTableConfig(
        'ipv4_fib', False,
        (('eth_type', False), ('ipv4_dst', True), ('vlan_vid', False)),
        ('eth_dst', 'eth_src', 'vlan_vid')),
    ValveTableConfig(
        'ipv6_fib', False,
        (('eth_type', False), ('ipv6_dst', True), ('vlan_vid', False)),
        ('eth_dst', 'eth_src', 'vlan_vid')),
    ValveTableConfig(
        'vip', False,
        (('arp_tpa', False), ('eth_dst', False), ('eth_type', False),
         ('icmpv6_type', False), ('ip_proto', False)),
        None),
    ValveTableConfig(
        'eth_dst', False,
        (('eth_dst', False), ('in_port', False), ('vlan_vid', False)),
        None),
    ValveTableConfig(
        'flood', False,
        (('eth_dst', True), ('in_port', False), ('vlan_vid', False)),
        None),
)
