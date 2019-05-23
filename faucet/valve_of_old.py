"""Deprecated OF matches."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Map of old field name, to new.
OLD_MATCH_FIELDS = {
    'dl_dst': 'eth_dst',
    'dl_src': 'eth_src',
    'dl_type': 'eth_type',
    'dl_vlan': 'vlan_vid',
    'nw_proto': 'ip_proto',
    'nw_src': 'ipv4_src',
    'nw_dst': 'ipv4_dst',
}
