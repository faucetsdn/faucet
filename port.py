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

class Port:
    number = None

    def __init__(self, number, conf=None):
        if conf is None:
            conf = {}
        self.number = number
        self.name = conf.setdefault('name', str(number))
        self.description = conf.setdefault('description', self.name)
        self.enabled = conf.setdefault('enabled', True)
        self.phys_up = False

    def running(self):
        return self.enabled and self.phys_up

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        return hash(('Port', self.number))

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return self.name
