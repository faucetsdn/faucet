"""Configure routing between VLANs."""

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

import pytricia

from faucet.conf import Conf, test_config_condition


class Router(Conf):
    """Implement FAUCET configuration for a router."""

    defaults = {
        'vlans': None,
    }

    defaults_types = {
        'vlans': list,
    }

    def __init__(self, _id, dp_id, conf):
        self.vlans = None
        self.vip_map = None
        super(Router, self).__init__(_id, dp_id, conf)

    def __str__(self):
        return self._id

    def check_config(self):
        super(Router, self).check_config()
        test_config_condition(not (isinstance(self.vlans, list) and len(self.vlans) > 1), (
            'router %s must have at least 2 VLANs configured' % self))

    def finalize(self):
        self.vip_map = pytricia.PyTricia(128)
        for vlan in self.vlans:
            for faucet_vip in vlan.faucet_vips:
                self.vip_map[faucet_vip.network] = (vlan, faucet_vip)
        super(Router, self).finalize()
