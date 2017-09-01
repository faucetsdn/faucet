"""Abstraction of an OF table."""

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


try:
    import valve_of
except ImportError:
    from faucet import valve_of


class ValveTable(object):
    """Wrapper for an OpenFlow table."""

    def __init__(self, table_id, name, restricted_match_types):
        self.table_id = table_id
        self.name = name
        self.restricted_match_types = None
        if restricted_match_types:
            self.restricted_match_types = set(restricted_match_types)

    def match(self, in_port=None, vlan=None,
              eth_type=None, eth_src=None,
              eth_dst=None, eth_dst_mask=None,
              ipv6_nd_target=None, icmpv6_type=None,
              nw_proto=None, nw_src=None, nw_dst=None):
        """Compose an OpenFlow match rule."""
        match_dict = valve_of.build_match_dict(
            in_port, vlan, eth_type, eth_src,
            eth_dst, eth_dst_mask, ipv6_nd_target, icmpv6_type,
            nw_proto, nw_src, nw_dst)
        match = valve_of.match(match_dict)
        if self.restricted_match_types is not None:
            for match_type in match_dict:
                assert match_type in self.restricted_match_types, '%s match in table %s' % (
                    match_type, self.name)
        return match
