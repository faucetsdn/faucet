"""Configure meters."""

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

from faucet.conf import Conf, test_config_condition
from faucet.valve_of import meteradd


class Meter(Conf):
    """Implement FAUCET configuration for an OpenFlow meter."""

    entry = None
    entry_msg = None
    meter_id = None

    defaults = {
        'entry': None,
        'meter_id': None,
    }

    defaults_types = {
        'entry': dict,
        'meter_id': int,
    }

    def __init__(self, _id, dp_id, conf):
        super(Meter, self).__init__(_id, dp_id, conf)
        assert conf['entry']
        assert conf['entry']['flags']
        assert conf['entry']['bands']
        conf['entry']['meter_id'] = self.meter_id
        self.entry_msg = meteradd(self.entry)

    def check_config(self):
        super().check_config()
        test_config_condition(
            self.meter_id < 0, 'meter_id is than 0')
        test_config_condition(
            self.meter_id > 4294901760,
            'DP meter_id cannot exceed 4294901760 per OF13 specification')
