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

from port import Port

class VLAN:
    vid = None
    tagged = None
    untagged = None

    def __init__(self, vid, ports=[]):
        self.vid = vid
        self.tagged = []
        self.untagged = []

        for port in ports:
            self.add_port(port)

    def __str__(self):
        ports = ",".join(map(str, self.get_ports()))
        return "vid:%s ports:%s" % (self.vid, ports)

    def get_ports(self):
        return self.tagged+self.untagged

    def add_port(self, port):
        if port.type == 'tagged':
            self.tagged.append(port)
        elif port.type == 'untagged':
            self.untagged.append(port)
