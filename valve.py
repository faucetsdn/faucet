# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
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

import logging

from collections import namedtuple

from util import mac_addr_is_unicast

from ryu.lib import ofctl_v1_3 as ofctl
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser


def valve_factory(dp):
    """Return a Valve object based dp's hardware configuration field.

    Different datapath hardware has different requirements for the valve
    implementation.

    Currently implemented is the OVSStatelessValve suitable for use with
    "Open vSwitch" and "Allied-Telesis"

    Arguments:
    dp -- a DP object with the configuration for this valve.
    """
    if dp.hardware == 'Open vSwitch'\
    or dp.hardware == 'Allied-Telesis':
        return OVSStatelessValve(dp)
    else:
        return None

class Valve(object):
    """Generates the messages to configure a datapath as a l2 learning switch.

    This is a non functional generic base class. The implementation of datapath
    entry/exit, port entry/exit and packet in messages are hardware dependant
    and therefore are unimplemented.
    """

    def __init__(self, *args, **kwargs):
        raise NotImplementedError

    def reload_config(self, new_dp):
        """Reload the config from new_dp

        KW Arguments:
        new_dp -- A new DP object containing the updated config."""
        raise NotImplementedError

    def datapath_connect(self, dp_id, ports):
        """Generate the default openflow msgs for a datapath upon connection.

        Depending on the implementation, a network state database may be
        updated.

        Arguments:
        dp_id -- the Datapath unique ID (64bit int)
        ports -- a list containing the port numbers of each port on the
            datapath.

        Returns:
        A list of flow mod messages that will be sent in order to the datapath
        in order to configure it."""

        raise NotImplementedError

    def datapath_disconnect(self, dp_id):
        """Update n/w state db upon disconnection of datapath with id dp_id."""
        raise NotImplementedError

    def port_add(self, dp_id, port_num):
        """Generate openflow msgs to update the datapath upon addition of port.

        Arguments:
        dp_id -- the unique id of the datapath
        port_num -- the port number of the new port

        Returns
        A list of flow mod messages to be sent to the datapath."""
        raise NotImplementedError

    def port_delete(self, dp_id, port_num):
        """Generate openflow msgs to update the datapath upon deletion of port.

        Returns
        A list of flow mod messages to be sent to the datapath."""
        raise NotImplementedError

    def rcv_packet(self, dp_id, in_port, vlan_vid, eth_src, eth_dst):
        """Generate openflow msgs to update datapath upon receipt of packet.

        This involves asssociating the ethernet source address of the packet
        with the given in_port (ethernet switching) ideally so that no packets
        from this address are sent to the controller, and packets to this
        address are output to in_port. This may not be fully possible depending
        on the limitations of the datapath.

        Depending on implementation this may involve updating a nw state db.

        Arguments:
        dp_id -- the unique id of the datapath that received the packet (64bit
            int)
        in_port -- the port number of the port that received the packet
        vlan_vid -- the vlan_vid tagged to the packet.
        eth_src -- the ethernet source address of the packet.

        Returns
        A list of flow mod messages to be sent to the datpath."""

        raise NotImplementedError


class OVSStatelessValve(Valve):
    """Valve implementation for Open vSwitch.

    Stateless because the controller does not keep track of the mac addresses,
    it just installs the necessary rules directly to the switch with
    timeouts."""

    def __init__(self, dp, logname='faucet', *args, **kwargs):
        self.dp = dp
        self.logger = logging.getLogger(logname)

    def ignore_port(self, port_num):
        """Ignore non-physical ports."""
        # port numbers > 0xF0000000 indicate a logical port
        return port_num > 0xF0000000

    def ignore_dpid(self, dp_id):
        """Ignore all DPIDs except the DPID configured."""
        if dp_id != self.dp.dp_id:
            self.logger.error("Unknown dpid:%s", dp_id)
            return True
        return False

    def all_valve_tables(self):
        return (
            self.dp.vlan_table,
            self.dp.acl_table,
            self.dp.eth_src_table,
            self.dp.eth_dst_table,
            self.dp.flood_table)

    def apply_actions(self, actions):
        return parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)

    def goto_table(self, table_id):
        return parser.OFPInstructionGotoTable(table_id)

    def valve_in_match(self, in_port=None, vlan=None,
                       eth_type=None, eth_src=None, eth_dst=None):
        match_dict = {}
        if in_port is not None:
            match_dict['in_port'] = in_port
        if vlan is not None:
            match_dict['vlan_vid'] = vlan.vid|ofp.OFPVID_PRESENT
        if eth_type is not None:
            match_dict['eth_type'] = eth_type
        if eth_src is not None:
            match_dict['eth_src'] = eth_src
        if eth_dst is not None:
            match_dict['eth_dst'] = eth_dst
        null_dp = namedtuple("null_dp", "ofproto_parser")
        null_dp.ofproto_parser = parser
        return ofctl.to_match(null_dp, match_dict)

    def valve_flowmod(self, table_id, match=None, priority=None,
                     inst=[], command=ofp.OFPFC_ADD, out_port=0,
                     out_group=0, hard_timeout=0, idle_timeout=0):
        """Helper function to construct a flow mod message with cookie."""
        if match is None:
            match = self.valve_in_match()
        if priority is None:
            priority = self.dp.lowest_priority
        return parser.OFPFlowMod(
            datapath=None,
            cookie=self.dp.cookie,
            command=command,
            table_id=table_id,
            priority=priority,
            out_port=out_port,
            out_group=out_group,
            match=match,
            instructions=inst,
            hard_timeout=hard_timeout,
            idle_timeout=idle_timeout)

    def valve_flowdel(self, table_id, match=None, priority=None,
                      out_port=ofp.OFPP_ANY):
        """Delete matching flows from a table."""
        return self.valve_flowmod(
            table_id,
            match=match,
            priority=priority,
            command=ofp.OFPFC_DELETE,
            out_port=out_port,
            out_group=ofp.OFPG_ANY)

    def valve_flowdrop(self, table_id, match=None, priority=None):
        """Add drop matching flow to a table."""
        return self.valve_flowmod(
            table_id,
            match=match,
            priority=priority,
            inst=[])

    def delete_all_valve_flows(self):
        """Delete all flows from Valve's tables."""
        ofmsgs = []
        for table_id in self.all_valve_tables():
            ofmsgs.append(self.valve_flowdel(table_id))
        return ofmsgs

    def add_default_drop_flows(self):
        """Add default drop rules."""
        ofmsgs = []

        # default drop on table 0.
        ofmsgs.append(self.valve_flowdrop(0, priority=self.dp.lowest_priority))

        # drop STDP BPDU
        for bpdu_mac in ("01:80:C2:00:00:00", "01:00:0C:CC:CC:CD"):
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                self.valve_in_match(eth_dst=bpdu_mac),
                priority=self.dp.highest_priority))

        # drop LLDP
        ofmsgs.append(self.valve_flowdrop(
            self.dp.vlan_table,
            self.valve_in_match(eth_type=ether.ETH_TYPE_LLDP),
            priority=self.dp.highest_priority))

        return ofmsgs

    def add_vlan_flood_flow(self):
        """Add a flow to flood packets for unknown destinations."""
        return [self.valve_flowmod(
            self.dp.eth_dst_table,
            inst=[self.goto_table(self.dp.flood_table)])]

    def add_controller_learn_flow(self):
        """Add a flow to allow the controller to learn and add flows for destinations."""
        inst = [
            self.apply_actions([parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]),
            self.goto_table(self.dp.eth_dst_table)
        ]
        return [self.valve_flowmod(
            self.dp.eth_src_table, priority=self.dp.low_priority, inst=inst)]

    def add_default_flows(self):
        """Configure datapath with necessary default tables and rules."""
        ofmsgs = []
        ofmsgs.extend(self.delete_all_valve_flows())
        ofmsgs.extend(self.add_default_drop_flows())
        ofmsgs.extend(self.add_vlan_flood_flow())
        ofmsgs.extend(self.add_controller_learn_flow())
        return ofmsgs

    def add_ports_and_vlans(self, discovered_port_nums):
        """Add all ports and VLANs from configuration and discovered from switch."""
        ofmsgs = []
        all_port_nums = set()

        # add vlan ports
        for vlan in self.dp.vlans.itervalues():
            self.logger.info("Configuring VLAN %s", vlan)
            vlan_ports = vlan.tagged + vlan.untagged
            for port in vlan_ports:
                all_port_nums.add(port.number)
            # install eth_dst_table flood ofmsgs
            ofmsgs.extend(self.build_flood_rules(vlan))

        # add mirror ports.
        for port_num in self.dp.mirror_from_port.itervalues():
            all_port_nums.add(port_num)

        # now configure all ports
        for port_num in all_port_nums:
            ofmsgs.extend(self.port_add(self.dp.dp_id, port_num))

        # add any ports discovered but not configured
        for port_num in discovered_port_nums:
            if self.ignore_port(port_num):
                continue
            if port_num not in all_port_nums:
                all_port_nums.add(port_num)

        return ofmsgs

    def build_flood_rule_actions(self, vlan):
        flood_acts = []
        for port in vlan.tagged:
            if port.running():
                flood_acts.append(parser.OFPActionOutput(port.number))
        if vlan.untagged:
            flood_acts.append(parser.OFPActionPopVlan())
            for port in vlan.untagged:
                if port.running():
                    flood_acts.append(parser.OFPActionOutput(port.number))
        return flood_acts

    def build_flood_rules(self, vlan, modify=False):
        """Add a flow to flood packets to unknown destinations on a VLAN."""
        command = ofp.OFPFC_ADD
        if modify:
            command = ofp.OFPFC_MODIFY_STRICT
        flood_priority = self.dp.low_priority
        flood_acts = self.build_flood_rule_actions(vlan)
        ofmsgs = []
        for port in vlan.tagged + vlan.untagged:
            if port.number in self.dp.mirror_from_port:
                mirror_port = self.dp.mirror_from_port[port.number]
                mirror_acts = [parser.OFPActionOutput(mirror_port)] + flood_acts
                ofmsgs.append(self.valve_flowmod(
                    self.dp.flood_table,
                    match=self.valve_in_match(in_port=port.number, vlan=vlan),
                    command=command,
                    inst=[self.apply_actions(mirror_acts)],
                    priority=flood_priority+1))
        ofmsgs.append(self.valve_flowmod(
            self.dp.flood_table,
            match=self.valve_in_match(vlan=vlan),
            command=command,
            inst=[self.apply_actions(flood_acts)],
            priority=flood_priority))
        return ofmsgs

    def datapath_connect(self, dp_id, discovered_port_nums):
        if self.ignore_dpid(dp_id):
            return []
        if discovered_port_nums is None:
            discovered_port_nums = []

        self.logger.info("Configuring datapath")
        ofmsgs = []
        ofmsgs.extend(self.add_default_flows())
        ofmsgs.extend(self.add_ports_and_vlans(discovered_port_nums))
        self.dp.running = True
        return ofmsgs

    def datapath_disconnect(self, dp_id):
        if not self.ignore_dpid(dp_id):
            self.logger.critical("Datapath disconnected")
        return []

    def datapath_down(self, dp_id):
        if self.ignore_dpid(dp_id):
            return []
        self.dp.running = False
        self.logger.warning("Datapath down {0}".format(dp_id))

    def port_add_acl(self, port_num):
        ofmsgs = []
        forwarding_table = self.dp.eth_src_table
        if port_num in self.dp.acl_in:
            acl_num = self.dp.acl_in[port_num]
            forwarding_table = self.dp.acl_table
            acl_rule_priority = self.dp.highest_priority
            acl_allow_inst = self.goto_table(self.dp.eth_src_table)
            for rule_conf in self.dp.acls[acl_num]:
                # default drop
                acl_inst = []
                match_dict = {}
                for attrib, attrib_value in rule_conf.iteritems():
                    if attrib == "allow":
                        if attrib_value == 1:
                            acl_inst.append(acl_allow_inst)
                        continue
                    if attrib == "in_port":
                        continue
                    match_dict[attrib] = attrib_value
                # override in_port always
                match_dict["in_port"] = port_num
                # to_match() needs to access parser via dp
                null_dp = namedtuple("null_dp", "ofproto_parser")
                null_dp.ofproto_parser = parser
                acl_match = ofctl.to_match(null_dp, match_dict)
                ofmsgs.append(self.valve_flowmod(
                    self.dp.acl_table,
                    acl_match,
                    priority=acl_rule_priority,
                    inst=acl_inst))
                acl_rule_priority = acl_rule_priority - 1
        return ofmsgs, forwarding_table

    def port_add_vlan_untagged(self, port, vlan, forwarding_table, mirror_act):
        ofmsgs = []
        vid = vlan.vid
        in_port_match = self.valve_in_match(in_port=port.number)
        push_vlan_act = mirror_act + [
            parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
            parser.OFPActionSetField(vlan_vid=vid|ofp.OFPVID_PRESENT)]
        push_vlan_inst = [
            self.apply_actions(push_vlan_act),
            self.goto_table(forwarding_table)
        ]
        ofmsgs.append(self.valve_flowmod(
            self.dp.vlan_table,
            in_port_match,
            priority=self.dp.low_priority,
            inst=push_vlan_inst))
        ofmsgs.extend(self.build_flood_rules(vlan))
        return ofmsgs

    def port_add_vlan_tagged(self, port, vlan, forwarding_table, mirror_act):
        ofmsgs = []
        vlan_inst = [
            self.apply_actions(mirror_act),
            self.goto_table(forwarding_table)
        ]
        ofmsgs.append(self.valve_flowmod(
            self.dp.vlan_table,
            self.valve_in_match(in_port=port.number, vlan=vlan),
            priority=self.dp.low_priority,
            inst=vlan_inst))
        ofmsgs.extend(self.build_flood_rules(vlan))
        return ofmsgs

    def port_add_vlans(self, port, forwarding_table, mirror_act):
        ofmsgs = []
        for vlan in self.dp.vlans.itervalues():
            if port in vlan.untagged:
                ofmsgs.extend(self.port_add_vlan_untagged(
                    port, vlan, forwarding_table, mirror_act))
            elif port in vlan.tagged:
                ofmsgs.extend(self.port_add_vlan_tagged(
                    port, vlan, forwarding_table, mirror_act))
        return ofmsgs

    def port_add(self, dp_id, port_num):
        if self.ignore_dpid(dp_id) or self.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            self.logger.info(
                "Autoconfiguring port:%u based on default config", port_num)
            self.dp.add_port(port_num)

        port = self.dp.ports[port_num]
        self.logger.info("Port added {0}".format(port))
        port.phys_up = True

        if not port.running():
            return []

        in_port_match = self.valve_in_match(in_port=port_num)
        ofmsgs = []
        self.logger.info("Sending config for port {0}".format(port))

        # delete eth_src_table, ACL, food rules
        for table in (self.dp.eth_src_table, self.dp.acl_table,
                      self.dp.flood_table):
            ofmsgs.append(self.valve_flowdel(table, in_port_match))

        if port_num in self.dp.mirror_from_port.values():
            # this is a mirror port - drop all input packets
            ofmsgs.append(self.valve_flowdrop(
                self.dp.vlan_table,
                in_port_match))
            return ofmsgs

        mirror_act = []
        # this port is mirrored to another port
        if port_num in self.dp.mirror_from_port:
            mirror_port_num = self.dp.mirror_from_port[port_num]
            mirror_act = [parser.OFPActionOutput(mirror_port_num)]

        acl_ofmsgs, forwarding_table = self.port_add_acl(port_num)
        ofmsgs.extend(acl_ofmsgs)
        ofmsgs.extend(self.port_add_vlans(port, forwarding_table, mirror_act))
        return ofmsgs

    def port_delete(self, dp_id, port_num):
        if self.ignore_dpid(dp_id) or self.ignore_port(port_num):
            return []

        if port_num not in self.dp.ports:
            return []

        port = self.dp.ports[port_num]
        port.phys_up = False

        self.logger.warning("Port down: {0}".format(port))

        ofmsgs = []

        # delete vlan_table rules
        ofmsgs.append(self.valve_flowdel(
            self.dp.vlan_table,
            self.valve_in_match(in_port=port_num),
            priority=self.dp.low_priority))

        # delete eth_dst rules
        ofmsgs.append(self.valve_flowdel(
            self.dp.eth_dst_table,
            out_port=port_num))

        ofmsgs.append(parser.OFPBarrierRequest(None))

        for vlan in self.dp.vlans.values():
            if port_num in vlan.tagged or port_num in vlan.untagged:
                ofmsgs.extend(self.build_flood_rules(vlan), modify=True)

        return ofmsgs

    def delete_host_from_vlan(self, eth_src, vlan):
        ofmsgs = []
        # delete any existing ofmsgs for this vlan/mac combination on the
        # src mac table
        ofmsgs.append(self.valve_flowdel(
            self.dp.eth_src_table,
            self.valve_in_match(vlan=vlan, eth_src=eth_src)))

        # delete any existing ofmsgs for this vlan/mac combination on the dst
        # mac table
        ofmsgs.append(self.valve_flowdel(
            self.dp.eth_dst_table,
            self.valve_in_match(vlan=vlan, eth_dst=eth_src)))

        ofmsgs.append(parser.OFPBarrierRequest(None))
        return ofmsgs

    def rcv_packet(self, dp_id, in_port, vlan_vid, eth_src, eth_dst):
        if self.ignore_dpid(dp_id) or self.ignore_port(in_port):
            return []

        if not self.dp.running:
            self.logger.error("Packet_in on unconfigured datapath")
            return []

        if in_port not in self.dp.ports:
            return []

        if not mac_addr_is_unicast(eth_src):
            self.logger.info(
                "Packet_in with multicast ethernet source address")
            return []

        self.logger.debug("Packet_in dp_id: %x src:%s in_port:%d vid:%s",
                         dp_id, eth_src, in_port, vlan_vid)

        vlan = self.dp.vlans[vlan_vid]
        ofmsgs = []
        ofmsgs.extend(self.delete_host_from_vlan(eth_src, vlan))

        mirror_acts = []
        if in_port in self.dp.mirror_from_port:
            mirror_port_num = self.dp.mirror_from_port[in_port]
            mirror_acts = [parser.OFPActionOutput(mirror_port_num)]

        # Update datapath to no longer send packets from this mac to controller
        # note the use of hard_timeout here and idle_timeout for the dst table
        # this is to ensure that the source rules will always be deleted before
        # any rules on the dst table. Otherwise if the dst table rule expires
        # but the src table rule is still being hit intermittantly the switch
        # will flood packets to that dst and not realise it needs to relearn
        # the rule
        ofmsgs.append(self.valve_flowmod(
            self.dp.eth_src_table,
            self.valve_in_match(in_port=in_port, vlan=vlan, eth_src=eth_src),
            priority=self.dp.high_priority,
            inst=[self.goto_table(self.dp.eth_dst_table)],
            hard_timeout=self.dp.timeout))

        # update datapath to output packets to this mac via the associated port
        if vlan.port_is_tagged(in_port):
            dst_act = [parser.OFPActionOutput(in_port)]
        else:
            dst_act = [
                parser.OFPActionPopVlan(),
                parser.OFPActionOutput(in_port)]
        if mirror_acts:
            dst_act.extend(mirror_acts)
        inst = [self.apply_actions(dst_act)]
        ofmsgs.append(self.valve_flowmod(
            self.dp.eth_dst_table,
            self.valve_in_match(vlan=vlan, eth_dst=eth_src),
            priority=self.dp.high_priority,
            inst=inst,
            idle_timeout=self.dp.timeout))

        return ofmsgs

    def reload_config(self, new_dp):
        if not self.dp.running:
            return []
        self.dp = new_dp
        return self.datapath_connect(self.dp.dp_id, self.dp.ports.keys())
