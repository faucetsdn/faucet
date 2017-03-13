# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
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

class Router(Conf):

    name = None
    vlans = None

    defaults = {
        'name': None,
        'vlans': None
        }

    def __init__(self, _id, name, conf=None):
        if conf is None:
            conf = {}
        self.name = name
        self.update(conf)
        self._id = _id

    def to_conf(self):
        return self._to_conf()
