"""Configuration for ACLs."""

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

from conf import Conf

class ACL(Conf):
    """Implement FAUCET configuration for an ACL."""

    rules = None
    defaults = {
        rules: None,
    }

    def __init__(self, _id, conf):
        if conf is None:
            conf = {}
        self._id = _id
        self.rules = [x['rule'] for x in conf]

    def to_conf(self):
        result = []
        for rule in self.rules:
            result.append({'rule': rule})
        return result
