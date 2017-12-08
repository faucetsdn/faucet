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

from faucet.conf import Conf


class ACL(Conf):
    """Contains the state for an ACL, including the configuration.

ACL Config

ACLs are configured under the 'acls' configuration block. The acls block
contains a dictionary of individual acls each keyed by its name.

Each acl contains a list of rules, a packet will have the first matching rule
applied to it.

Each rule is a dictionary containing the single key 'rule' with the value the
matches and actions for the rule.

The matches are key/values based on the ryu RESTFul API.
The key 'actions' contains a dictionary with keys/values as follows:

 * allow (bool): if True allow the packet to continue through the Faucet
     pipeline, if False drop the packet.
 * meter (str): meter to apply to the packet
 * output (dict): used to output a packet directly. details below.

The output action contains a dictionary with the following elements:

 * port (int or string): the port to output the packet to
 * swap_vid (int): rewrite the vlan vid of the packet when outputting
 * failover (dict): Output with a failover port. The following elements can be
     configured.
     * group_id (int): the ofp group id to use for the group
     * ports (list): a list of the ports the packet can be output through
"""

    # Resolved port numbers which are mirror action destinations.
    mirror_destinations = set()
    rules = None
    exact_match = None
    defaults = {
        'rules': None,
        'exact_match': False,
    }
    defaults_types = {
        'rules': list,
        'exact_match': bool,
    }

    def __init__(self, _id, dp_id, conf):
        super(ACL, self).__init__(_id, dp_id, conf)
        # TODO: ACL rule content should be type checked.
        rules = conf
        if isinstance(conf, dict):
            if 'exact_match' in conf and conf['exact_match']:
                self.exact_match = True
            rules = conf['rules']
        self.rules = []
        assert isinstance(rules, list)
        for rule in rules:
            assert isinstance(rule, dict)
            for rule_key, rule_content in list(rule.items()):
                assert rule_key == 'rule'
                assert isinstance(rule_content, dict)
                self.rules.append(rule_content)

    def to_conf(self):
        return [{'rule': rule} for rule in self.rules]
