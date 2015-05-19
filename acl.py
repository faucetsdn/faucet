# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
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

import collections

class ACL:
    match = None
    action = None

    def __init__(self, match, action):
        self.match = match
        self.action = action

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            a = collections.Counter(self.match)
            b = collections.Counter(other.match)
            return a == b
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        s = []
        for k in self.match:
            s.append("%s=%s" % (k, self.match[k]))
        return "%s actions=%s" % (",".join(s), self.action)
