"""Standard FAUCET pipeline."""

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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

from faucet.faucet_metadata import EGRESS_METADATA_MASK


class ValveTableConfig: # pylint: disable=too-few-public-methods,too-many-instance-attributes
    """Configuration for a single table."""

    def __init__(self, name, table_id, # pylint: disable=too-many-arguments
                 exact_match=None, meter=None, output=True, miss_goto=None,
                 size=None, match_types=None, set_fields=None, dec_ttl=None,
                 vlan_scale=None, vlan_port_scale=None,
                 next_tables=None, metadata_match=0, metadata_write=0):
        self.name = name
        self.table_id = table_id
        self.exact_match = exact_match
        self.meter = meter
        self.output = output
        self.miss_goto = miss_goto
        self.size = size
        self.match_types = match_types
        self.set_fields = set_fields
        self.dec_ttl = dec_ttl
        self.vlan_scale = vlan_scale
        self.vlan_port_scale = vlan_port_scale
        self.metadata_match = metadata_match
        self.metadata_write = metadata_write
        if next_tables:
            assert isinstance(next_tables, (list, tuple))
            self.next_tables = next_tables
        else:
            self.next_tables = ()

    def __str__(self):
        field_strs = ' '.join([
            '%s: %s' % (key, val)
            for key, val in sorted(self.__dict__.items())
            if val])
        return 'table config %s' % field_strs

    def __repr__(self):
        return self.__str__()

    def __hash__(self):
        return hash(self.__str__())

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __lt__(self, other):
        return self.__hash__() < other.__hash__()


_NEXT_ETH = ('eth_dst_hairpin', 'eth_dst', 'flood')
_NEXT_VIP = ('vip',) + _NEXT_ETH


def _fib_table(ipv, table_id):
    return ValveTableConfig(
        'ipv%u_fib' % ipv,
        table_id,
        match_types=(('eth_type', False), ('ipv%u_dst' % ipv, True), ('vlan_vid', False)),
        set_fields=('eth_dst', 'eth_src', 'vlan_vid'),
        dec_ttl=True,
        vlan_port_scale=3.1,
        next_tables=_NEXT_VIP
        )

PORT_ACL_DEFAULT_CONFIG = ValveTableConfig(
    'port_acl',
    0,
    match_types=(('in_port', False),),
    next_tables=(('vlan',) + _NEXT_VIP)
    )
VLAN_DEFAULT_CONFIG = ValveTableConfig(
    'vlan',
    PORT_ACL_DEFAULT_CONFIG.table_id + 1,
    match_types=(('eth_dst', True), ('eth_type', False),
                 ('in_port', False), ('vlan_vid', False)),
    set_fields=('vlan_vid',),
    vlan_port_scale=1.5,
    next_tables=('copro', 'vlan_acl', 'classification', 'eth_src')
    )
COPRO_DEFAULT_CONFIG = ValveTableConfig(
    'copro',
    VLAN_DEFAULT_CONFIG.table_id + 1,
    match_types=(('in_port', False), ('eth_type', False), ('vlan_vid', False)),
    vlan_port_scale=1.5,
    miss_goto='eth_dst',
    next_tables=(('eth_dst',)),
    )
VLAN_ACL_DEFAULT_CONFIG = ValveTableConfig(
    'vlan_acl',
    VLAN_DEFAULT_CONFIG.table_id + 1,
    next_tables=(('classification', 'eth_src') + _NEXT_ETH))
CLASSIFICATION_DEFAULT_CONFIG = ValveTableConfig(
    'classification',
    VLAN_ACL_DEFAULT_CONFIG.table_id + 1,
    miss_goto='eth_src',
    next_tables=(('eth_src', 'ipv4_fib', 'ipv6_fib') + _NEXT_VIP)
    )
ETH_SRC_DEFAULT_CONFIG = ValveTableConfig(
    'eth_src',
    CLASSIFICATION_DEFAULT_CONFIG.table_id + 1,
    miss_goto='eth_dst',
    next_tables=(('ipv4_fib', 'ipv6_fib') + _NEXT_VIP),
    match_types=(('eth_dst', True), ('eth_src', False), ('eth_type', False),
                 ('in_port', False), ('vlan_vid', False)),
    set_fields=('vlan_vid', 'eth_dst'),
    vlan_port_scale=4.1,
    )
IPV4_FIB_DEFAULT_CONFIG = _fib_table(4, ETH_SRC_DEFAULT_CONFIG.table_id + 1)
IPV6_FIB_DEFAULT_CONFIG = _fib_table(6, IPV4_FIB_DEFAULT_CONFIG.table_id + 1)
VIP_DEFAULT_CONFIG = ValveTableConfig(
    'vip',
    IPV6_FIB_DEFAULT_CONFIG.table_id + 1,
    match_types=(('arp_tpa', False), ('eth_dst', False), ('eth_type', False),
                 ('icmpv6_type', False), ('ip_proto', False)),
    next_tables=_NEXT_ETH,
    vlan_scale=8,
    )
ETH_DST_HAIRPIN_DEFAULT_CONFIG = ValveTableConfig(
    'eth_dst_hairpin',
    VIP_DEFAULT_CONFIG.table_id + 1,
    match_types=(('in_port', False), ('eth_dst', False), ('vlan_vid', False)),
    miss_goto='eth_dst',
    exact_match=True,
    vlan_port_scale=4.1,
    )
ETH_DST_DEFAULT_CONFIG = ValveTableConfig(
    'eth_dst',
    ETH_DST_HAIRPIN_DEFAULT_CONFIG.table_id + 1,
    exact_match=True,
    miss_goto='flood', # Note: when using egress acls the miss goto will be
                       # egress acl table
    match_types=(('eth_dst', False), ('vlan_vid', False)),
    next_tables=('egress', 'egress_acl'),
    vlan_port_scale=4.1,
    metadata_write=EGRESS_METADATA_MASK
    )
EGRESS_ACL_DEFAULT_CONFIG = ValveTableConfig(
    'egress_acl',
    ETH_DST_DEFAULT_CONFIG.table_id + 1,
    next_tables=('egress',)
    )
EGRESS_DEFAULT_CONFIG = ValveTableConfig(
    'egress',
    EGRESS_ACL_DEFAULT_CONFIG.table_id + 1,
    match_types=(('metadata', True), ('vlan_vid', False)),
    vlan_port_scale=1.5,
    next_tables=('flood',),
    miss_goto='flood',
    metadata_match=EGRESS_METADATA_MASK
    )
FLOOD_DEFAULT_CONFIG = ValveTableConfig(
    'flood',
    EGRESS_DEFAULT_CONFIG.table_id + 1,
    match_types=(('eth_dst', True), ('in_port', False), ('vlan_vid', False)),
    vlan_port_scale=7.0,
    )
MINIMUM_FAUCET_PIPELINE_TABLES = {
    'vlan', 'eth_src', 'eth_dst', 'flood'}

# TODO: implement an eth_type table before VLAN. This would enable interception
# of control protocols and simplify matches in vlan/eth_src, enabling use of
# exact_match.
FAUCET_PIPELINE = (
    PORT_ACL_DEFAULT_CONFIG,
    VLAN_DEFAULT_CONFIG,
    COPRO_DEFAULT_CONFIG,
    VLAN_ACL_DEFAULT_CONFIG,
    CLASSIFICATION_DEFAULT_CONFIG,
    ETH_SRC_DEFAULT_CONFIG,
    IPV4_FIB_DEFAULT_CONFIG,
    IPV6_FIB_DEFAULT_CONFIG,
    VIP_DEFAULT_CONFIG,
    ETH_DST_HAIRPIN_DEFAULT_CONFIG,
    ETH_DST_DEFAULT_CONFIG,
    EGRESS_ACL_DEFAULT_CONFIG,
    EGRESS_DEFAULT_CONFIG,
    FLOOD_DEFAULT_CONFIG,
)

DEFAULT_CONFIGS = {
    'port_acl': PORT_ACL_DEFAULT_CONFIG,
    'vlan': VLAN_DEFAULT_CONFIG,
    'copro': COPRO_DEFAULT_CONFIG,
    'vlan_acl': VLAN_ACL_DEFAULT_CONFIG,
    'eth_src': ETH_SRC_DEFAULT_CONFIG,
    'ipv4_fib': IPV4_FIB_DEFAULT_CONFIG,
    'ipv6_fib': IPV6_FIB_DEFAULT_CONFIG,
    'vip': VIP_DEFAULT_CONFIG,
    'eth_dst_hairpin': ETH_DST_HAIRPIN_DEFAULT_CONFIG,
    'eth_dst': ETH_DST_DEFAULT_CONFIG,
    'egress_acl': EGRESS_ACL_DEFAULT_CONFIG,
    'egress': EGRESS_DEFAULT_CONFIG,
    'flood': FLOOD_DEFAULT_CONFIG,
}
