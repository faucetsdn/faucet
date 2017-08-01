"""Configure meters."""

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

from ryu.lib import ofctl_v1_3 as ofctl
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser


try:
    from conf import Conf
except ImportError:
    from faucet.conf import Conf


class NoopDP(object):

    id = 0
    msg = None

    def send_msg(self, msg):
        self.msg = msg

    def set_xid(self, msg):
        msg.xid = 0


class Meter(Conf):
    """Implement FAUCET configuration for an OpenFlow meter."""

    name = None
    entry_msg = None

    defaults = {
        'entry': None,
    }

    defaults_type = {
        'entry': dict,
    }

    def __init__(self, _id, conf=None):
        if conf is None:
            conf = {}
        self.update(conf)
        self._id = _id
        noop_dp = NoopDP()
        noop_dp.ofproto = ofp
        noop_dp.ofproto_parser = parser
        ofctl.mod_meter_entry(noop_dp, self.entry, ofp.OFPMC_ADD)
        self.entry_msg = noop_dp.msg
