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

from util import mac_addr_is_unicast

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

    def port_add(self, dp_id, port):
        """Generate openflow msgs to update the datapath upon addition of port.

        Arguments:
        dp_id -- the unique id of the datapath
        port -- the port number of the new port

        Returns
        A list of flow mod messages to be sent to the datapath."""
        raise NotImplementedError

    def port_delete(self, dp_id, portnum):
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

    def datapath_connect(self, dp_id, ports):
        if dp_id != self.dp.dp_id:
            self.logger.error("Unknown dpid:%s", dp_id)
            return []
        else:
            datapath = self.dp

        for port in ports:
            # port numbers > 0xF0000000 indicate a logical port
            if port > 0xF0000000:
                continue
            elif port not in datapath.ports:
                # Autoconfigure port
                self.logger.info(
                    "Autoconfiguring port:%s based on default config", port)
                datapath.add_port(port)
            datapath.ports[port].phys_up = True

        self.logger.info("Configuring datapath")

        # flow_mods to be installed
        ofmsgs = []

        # default values used in flow mods
        match_all = parser.OFPMatch()
        vlan_table_id = datapath.vlan_table
        src_table_id = datapath.eth_src_table
        dst_table_id = datapath.eth_dst_table
        flood_table_id = datapath.flood_table
        low_priority = datapath.low_priority
        high_priority = datapath.high_priority
        lowest_priority = datapath.lowest_priority
        highest_priority = datapath.highest_priority
        cookie = datapath.cookie

        # Hard reset when datapath connects
        for table_id in (vlan_table_id, src_table_id, dst_table_id, flood_table_id):
            mod = parser.OFPFlowMod(
                datapath=None,
                cookie=cookie,
                command=ofp.OFPFC_DELETE,
                table_id=table_id,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=match_all)
            ofmsgs.append(mod)

        # install STDP BPDU and LLDP drop actions
        for bpdu_mac in ("01:80:C2:00:00:00", "01:00:0C:CC:CC:CD"):
            match_stp_bpdu = parser.OFPMatch(eth_dst=bpdu_mac)
            mod = parser.OFPFlowMod(
                datapath=None,
                cookie=cookie,
                table_id=vlan_table_id,
                priority=highest_priority,
                match=match_stp_bpdu,
                instructions=[])
            ofmsgs.append(mod)

        match_lldp = parser.OFPMatch(eth_type=ether.ETH_TYPE_LLDP)
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=cookie,
            table_id=vlan_table_id,
            priority=highest_priority,
            match=match_lldp,
            instructions=[])
        ofmsgs.append(mod)

        # install vlan_table miss action
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=cookie,
            table_id=vlan_table_id,
            priority=lowest_priority,
            match=match_all,
            instructions=[])
        ofmsgs.append(mod)

        # install eth_dst miss action
        goto_flood_instruction = parser.OFPInstructionGotoTable(flood_table_id)
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=cookie,
            table_id=dst_table_id,
            priority=lowest_priority,
            match=match_all,
            instructions=[goto_flood_instruction])
        ofmsgs.append(mod)

        # install vlan actions
        goto_src_inst = parser.OFPInstructionGotoTable(src_table_id)
        for vlan_vid, vlan in datapath.vlans.items():
            self.logger.info("Configuring %s", vlan)

            # The correct vlan_id is pushed upon all packets, to simplify the
            # eth_dst_table
            # Packets are forwarded to the eth_src_table (with vlan tags) to
            # determine whether the mac needs to be learned.
            for port in vlan.tagged:
                port_match = parser.OFPMatch(
                    in_port=port.number,
                    vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)
                mod = parser.OFPFlowMod(
                    datapath=None,
                    cookie=cookie,
                    table_id=vlan_table_id,
                    priority=high_priority,
                    match=port_match,
                    instructions=[goto_src_inst])
                ofmsgs.append(mod)

            for port in vlan.untagged:
                port_match = parser.OFPMatch(in_port=port.number)
                push_vlan_act = [
                  parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                  parser.OFPActionSetField(vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)]
                push_vlan_inst = parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS, push_vlan_act)
                mod = parser.OFPFlowMod(
                    datapath=None,
                    cookie=cookie,
                    table_id=vlan_table_id,
                    priority=low_priority,
                    match=port_match,
                    instructions=[push_vlan_inst, goto_src_inst])
                ofmsgs.append(mod)

            # install eth_src_table default controller flow mod
            controller_act = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
            controller_inst = parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, controller_act)
            goto_dst_inst = parser.OFPInstructionGotoTable(dst_table_id)
            mod = parser.OFPFlowMod(
                datapath=None,
                cookie=cookie,
                table_id=src_table_id,
                priority=lowest_priority,
                match=match_all,
                instructions=[controller_inst, goto_dst_inst])
            ofmsgs.append(mod)

            # install eth_dst_table flood ofmsgs
            ofmsgs.append(self.build_flood_rule(vlan))

        # Mark datapath as fully configured
        datapath.running = True

        self.logger.info("Datapath configured")

        return ofmsgs

    def datapath_disconnect(self, dp_id):
        if dp_id != self.dp.dp_id:
            self.logger.error("Unknown dpid:%s", dp_id)
        self.logger.critical("Datapath disconnected")

    def build_flood_rule(self, vlan, modify=False):
        # install eth_dst_table flood ofmsgs
        if modify:
            command = ofp.OFPFC_MODIFY_STRICT
        else:
            command = ofp.OFPFC_ADD
        match = parser.OFPMatch(vlan_vid=vlan.vid|ofp.OFPVID_PRESENT)
        act = []
        for port in vlan.tagged:
            if port.running():
                act.append(parser.OFPActionOutput(port.number))
        act.append(parser.OFPActionPopVlan())
        for port in vlan.untagged:
            if port.running():
                act.append(parser.OFPActionOutput(port.number))
        instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, act)]
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=self.dp.cookie,
            command=command,
            table_id=self.dp.flood_table,
            priority=self.dp.lowest_priority,
            match=match,
            instructions=instructions)
        return mod

    def datapath_down(self, dp_id):
        if dp_id != self.dp.dp_id:
            return
        self.dp.running = False
        self.logger.warning("Datapath down {0}".format(dp_id))

    def port_add(self, dp_id, portnum):
        if dp_id != self.dp.dp_id:
            return
        # These are special port numbers
        if portnum > 0xF0000000:
            return

        if portnum not in self.dp.ports:
            # Autoconfigure port
            self.logger.info(
                "Autoconfiguring port:%s based on default config", portnum)
            self.dp.add_port(portnum)

        port = self.dp.ports[portnum]

        self.logger.info("Port added {0}".format(port))

        port.phys_up = True

        ofmsgs = []
        if port.running():
            self.logger.info("Sending config for port {0}".format(port))

            # delete eth_src_table rules
            eth_src_match = parser.OFPMatch(in_port=portnum)
            mod = parser.OFPFlowMod(
                datapath=None,
                cookie=self.dp.cookie,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                table_id=self.dp.eth_src_table,
                match=eth_src_match)
            ofmsgs.append(mod)

            # add vlan_table rules
            for vid, vlan in self.dp.vlans.iteritems():
                if port in vlan.untagged:
                    port_match = parser.OFPMatch(in_port=port.number)
                    push_vlan_act = [
                        parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                        parser.OFPActionSetField(vlan_vid=vid|ofp.OFPVID_PRESENT)]
                    push_vlan_inst = [
                        parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, push_vlan_act),
                        parser.OFPInstructionGotoTable(self.dp.eth_src_table)]
                    mod = parser.OFPFlowMod(
                        datapath=None,
                        cookie=self.dp.cookie,
                        table_id=self.dp.vlan_table,
                        priority=self.dp.low_priority,
                        match=port_match,
                        instructions=push_vlan_inst)
                    ofmsgs.append(mod)
                elif port in vlan.tagged:
                    port_match = parser.OFPMatch(
                        in_port=port.number,
                        vlan_vid=vid|ofp.OFPVID_PRESENT)
                    vlan_inst = [
                        parser.OFPInstructionGotoTable(self.dp.eth_src_table)]
                    mod = parser.OFPFlowMod(
                        datapath=None,
                        cookie=self.dp.cookie,
                        table_id=self.dp.vlan_table,
                        priority=self.dp.low_priority,
                        match=port_match,
                        instructions=vlan_inst)
                    ofmsgs.append(mod)

            # modify eth_dst rules
            for vid, vlan in self.dp.vlans.iteritems():
                if port in vlan.tagged:
                    ofmsgs.append(self.build_flood_rule(vlan))
                elif port in vlan.untagged:
                    ofmsgs.append(self.build_flood_rule(vlan))

        return ofmsgs

    def port_delete(self, dp_id, portnum):
        if dp_id != self.dp.dp_id:
            return
        if portnum not in self.dp.ports:
            return
        port = self.dp.ports[portnum]
        port.phys_up = False

        self.logger.warning("Port down: {0}".format(port))

        ofmsgs = []

        # delete vlan_table rules
        vlan_table_match = parser.OFPMatch(in_port=portnum)
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=self.dp.cookie,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            table_id=self.dp.vlan_table,
            priority=self.dp.low_priority,
            match=vlan_table_match)
        ofmsgs.append(mod)

        # delete eth_dst rules
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=self.dp.cookie,
            command=ofp.OFPFC_DELETE,
            out_port=portnum,
            out_group=ofp.OFPG_ANY,
            table_id=self.dp.eth_dst_table,
            match=parser.OFPMatch())
        ofmsgs.append(mod)

        ofmsgs.append(parser.OFPBarrierRequest(None))

        for vlan in self.dp.vlans.values():
            if portnum in vlan.tagged:
                ofmsgs.append(self.build_flood_rule(vlan), modify=True)
            elif portnum in vlan.untagged:
                ofmsgs.append(self.build_flood_rule(vlan), modify=True)

        return ofmsgs

    def rcv_packet(self, dp_id, in_port, vlan_vid, eth_src, eth_dst):
        if dp_id != self.dp.dp_id:
            self.logger.error("Packet_in on unknown datapath")
            return []
        else:
            datapath = self.dp

        if not datapath.running:
            self.logger.error("Packet_in on unconfigured datapath")

        if in_port not in datapath.ports:
            return []

        if not mac_addr_is_unicast(eth_src):
            self.logger.info(
                "Packet_in with multicast ethernet source address")
            return []

        self.logger.debug("Packet_in dp_id: %x src:%s in_port:%d vid:%s",
                         dp_id, eth_src, in_port, vlan_vid)

        tagged = datapath.vlans[vlan_vid].port_is_tagged(in_port)

        # flow_mods to be installed
        ofmsgs = []

        # default values used in flow mods
        src_table_id = datapath.eth_src_table
        dst_table_id = datapath.eth_dst_table
        high_priority = datapath.high_priority
        timeout = datapath.timeout
        cookie = datapath.cookie

        # delete any existing ofmsgs for this vlan/mac combination on the
        # src mac table
        src_delete_match = parser.OFPMatch(
            eth_src=eth_src,
            vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=cookie,
            table_id=src_table_id,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=src_delete_match)
        ofmsgs.append(mod)

        # delete any existing ofmsgs for this vlan/mac combination on the dst
        # mac table
        dst_delete_match = parser.OFPMatch(
            eth_dst=eth_src,
            vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=cookie,
            table_id=dst_table_id,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=dst_delete_match)
        ofmsgs.append(mod)

        ofmsgs.append(parser.OFPBarrierRequest(None))

        # Update datapath to no longer send packets from this mac to controller
        # note the use of hard_timeout here and idle_timeout for the dst table
        # this is to ensure that the source rules will always be deleted before
        # any rules on the dst table. Otherwise if the dst table rule expires
        # but the src table rule is still being hit intermittantly the switch
        # will flood packets to that dst and not realise it needs to relearn
        # the rule
        src_match = parser.OFPMatch(
            in_port=in_port,
            eth_src=eth_src,
            vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)
        instructions = [parser.OFPInstructionGotoTable(dst_table_id)]
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=cookie,
            hard_timeout=timeout,
            table_id=src_table_id,
            priority=high_priority,
            match=src_match,
            instructions=instructions)
        ofmsgs.append(mod)

        # update datapath to output packets to this mac via the associated port
        dst_match = parser.OFPMatch(
            eth_dst=eth_src,
            vlan_vid=vlan_vid|ofp.OFPVID_PRESENT)
        if tagged:
            dst_act = [parser.OFPActionOutput(in_port)]
        else:
            dst_act = [
                parser.OFPActionPopVlan(),
                parser.OFPActionOutput(in_port)]
        instructions = [
            parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, dst_act)]
        mod = parser.OFPFlowMod(
            datapath=None,
            cookie=cookie,
            idle_timeout=timeout,
            table_id=dst_table_id,
            priority=high_priority,
            match=dst_match,
            instructions=instructions)
        ofmsgs.append(mod)

        return ofmsgs

    def reload_config(self, new_dp):
        if not self.dp.running:
            return []

        # It would be better to actually check the state of the dp flow table
        # when you do this. I am leaving this for now because I think it would
        # be better to use a controller that provides such features natively
        # rather than trying to implement that myself.

        # check if stuff like the table offset changes - at least error if that
        # is the case

        ofmsgs = []
        old_dp = self.dp

        # update the state of the dp/port
        new_dp.running = old_dp.running

        for portnum, port in old_dp.ports.iteritems():
            if portnum in new_dp.ports:
                new_dp.ports[portnum].phys_up = port.phys_up
            else:
                port.enabled = False
                new_dp.ports[portnum] = port

        all_vlans = set(new_dp.vlans.keys()) | set(old_dp.vlans.keys())
        for vid in all_vlans:
            # work out what needs to be changed
            new_untagged = set([])
            new_tagged = set([])
            if vid in new_dp.vlans:
                new_untagged = set([x for x in new_dp.vlans[vid].untagged if x.running()])
                new_tagged = set([x for x in new_dp.vlans[vid].tagged if x.running()])
            old_untagged = set([])
            old_tagged = set([])
            if vid in old_dp.vlans:
                old_untagged = set([x for x in old_dp.vlans[vid].untagged if x.running()])
                old_tagged = set([x for x in old_dp.vlans[vid].tagged if x.running()])

            added_untagged = new_untagged - old_untagged
            removed_untagged = old_untagged - new_untagged
            added_tagged = new_tagged - old_tagged
            removed_tagged = old_tagged - new_tagged

            # remove vlan table rules
            for port in removed_untagged:
                match = parser.OFPMatch(in_port=port.number)
                mod = parser.OFPFlowMod(
                    datapath=None,
                    cookie=old_dp.cookie,
                    command=ofp.OFPFC_DELETE_STRICT,
                    table_id=old_dp.vlan_table,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    priority=old_dp.low_priority,
                    match=match)
                ofmsgs.append(mod)

            for port in removed_tagged:
                match = parser.OFPMatch(
                    in_port=port.number,
                    vlan_vid=vid|ofp.OFPVID_PRESENT)
                mod = parser.OFPFlowMod(
                    datapath=None,
                    cookie=old_dp.cookie,
                    command=ofp.OFPFC_DELETE_STRICT,
                    table_id=old_dp.vlan_table,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                    priority=old_dp.high_priority,
                    match=match)
                ofmsgs.append(mod)

            # remove learned dst macs
            for port in removed_untagged | removed_tagged:
                match = parser.OFPMatch(vlan_vid=vid|ofp.OFPVID_PRESENT)
                mod = parser.OFPFlowMod(
                    datapath=None,
                    cookie=old_dp.cookie,
                    command=ofp.OFPFC_DELETE,
                    out_group=ofp.OFPG_ANY,
                    table_id=old_dp.eth_dst_table,
                    priority=old_dp.high_priority,
                    match=match,
                    out_port=port.number)
                ofmsgs.append(mod)

            ofmsgs.append(parser.OFPBarrierRequest(None))

            # change flood rules
            ofmsgs.append(self.build_flood_rule(new_dp.vlans[vid], True))

            # add vlan table rules
            goto_src_inst = parser.OFPInstructionGotoTable(new_dp.eth_src_table)

            for port in added_tagged:
                self.logger.debug(
                    "sending config for port {0} on vlan {1}".format(port, new_dp.vlans[vid]))
                port_match = parser.OFPMatch(
                    in_port=port.number,
                    vlan_vid=vid|ofp.OFPVID_PRESENT)
                mod = parser.OFPFlowMod(
                    datapath=None,
                    cookie=new_dp.cookie,
                    table_id=new_dp.vlan_table,
                    priority=new_dp.high_priority,
                    match=port_match,
                    instructions=[goto_src_inst])
                ofmsgs.append(mod)

            for port in added_untagged:
                self.logger.debug(
                    "sending config for port {0} on vlan {1}".format(port, new_dp.vlans[vid]))
                port_match = parser.OFPMatch(in_port=port.number)
                push_vlan_act = [
                  parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
                  parser.OFPActionSetField(vlan_vid=vid|ofp.OFPVID_PRESENT)]
                push_vlan_inst = parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS, push_vlan_act)
                mod = parser.OFPFlowMod(
                    datapath=None,
                    cookie=new_dp.cookie,
                    table_id=new_dp.vlan_table,
                    priority=new_dp.low_priority,
                    match=port_match,
                    instructions=[push_vlan_inst, goto_src_inst])
                ofmsgs.append(mod)

            # adding ofmsgs to remove learned source mac addresses on changed
            # ports isnt necessary, they will be relearned. However it may be
            # prudent to do it anyway in order to reduce the number of
            # flow rules used. I doubt it will be a big deal though.

        self.dp = new_dp

        return ofmsgs
