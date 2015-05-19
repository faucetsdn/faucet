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

from acl import ACL

class Port:
    number = None
    type = None
    acls = None

    def __init__(self, number, type, acls = []):
        self.number = number
        self.type = type
        self.acls = acls

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            same_number = (self.number == other.number)
            same_type = (self.type == other.type)
            return same_number and same_number
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        port_desc = "%s(%s)" % (self.number, self.type)
        return port_desc

    def add_acl(self, acl):
        if acl not in self.acls:
            self.acls.append(acl)

    def is_tagged(self):
        return (self.type == 'tagged')

    def is_untagged(self):
        return (self.type == 'untagged')
