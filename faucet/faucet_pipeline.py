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

    def __init__(self, name, exact_match=None, meter=None, output=True,
                 miss_goto=None, match_types=None, set_fields=None):
        self.name = name
        self.exact_match = exact_match
        self.meter = meter
        self.output = output
        self.miss_goto = miss_goto
        self.match_types = match_types
        self.set_fields = set_fields

    def __str__(self):
        return 'table config: %s exact match: %s meter: %s match types: %s set_fields: %s' % (
            self.name, self.exact_match, self.meter, self.match_types, self.set_fields)

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __lt__(self, other):
        return self.__hash__() < other.__hash__()


def _fib_table(ipv):
    return ValveTableConfig(
        'ipv%u_fib' % ipv,
        match_types=(('eth_type', False), ('ipv%u_dst' % ipv, True), ('vlan_vid', False)),
        set_fields=('eth_dst', 'eth_src', 'vlan_vid'))


FAUCET_PIPELINE = (
    ValveTableConfig(
        'port_acl'),
    ValveTableConfig(
        'vlan',
        match_types=(('eth_dst', True), ('eth_type', False),
                     ('in_port', False), ('vlan_vid', False)),
        set_fields=('vlan_vid',)),
    ValveTableConfig(
        'vlan_acl'),
    ValveTableConfig(
        'eth_src',
        miss_goto='eth_dst',
        match_types=(('eth_dst', True), ('eth_src', False), ('eth_type', False),
                     ('in_port', False), ('vlan_vid', False))),
    _fib_table(4),
    _fib_table(6),
    ValveTableConfig(
        'vip',
        match_types=(('arp_tpa', False), ('eth_dst', False), ('eth_type', False),
                     ('icmpv6_type', False), ('ip_proto', False))),
    ValveTableConfig(
        'eth_dst',
        match_types=(('eth_dst', False), ('in_port', False), ('vlan_vid', False))),
    ValveTableConfig(
        'flood',
        match_types=(('eth_dst', True), ('in_port', False), ('vlan_vid', False))),
)
