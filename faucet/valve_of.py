"""Utility functions to parse/create OpenFlow messages."""

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import functools
import ipaddress
import random

from ryu.lib import mac
from ryu.lib import ofctl_v1_3 as ofctl
from ryu.lib.ofctl_utils import (
    str_to_int, to_match_ip, to_match_masked_int, to_match_eth, to_match_vid, OFCtlUtil)
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

from faucet.conf import test_config_condition, InvalidConfigError
from faucet.valve_of_old import OLD_MATCH_FIELDS

MIN_VID = 1
MAX_VID = 4095
VLAN_GROUP_OFFSET = MAX_VID + 1
ROUTE_GROUP_OFFSET = VLAN_GROUP_OFFSET * 2
OFP_VERSIONS = [ofp.OFP_VERSION]
OFP_IN_PORT = ofp.OFPP_IN_PORT
MAX_PACKET_IN_BYTES = 194  # largest packet is icmp6 echo req with 128 byte payload
ECTP_ETH_TYPE = 0x9000

# https://en.wikipedia.org/wiki/IEEE_P802.1p
# Avoid use of PCP 1 which is BK priority (lowest)
PCP_EXT_PORT_FLAG = 2
PCP_NONEXT_PORT_FLAG = 0
EXTERNAL_FORWARDING_FIELD = 'vlan_pcp'


OFERROR_TYPE_CODE = {
    0: ('OFPET_HELLO_FAILED', {
        ofp.OFPHFC_INCOMPATIBLE: 'OFPHFC_INCOMPATIBLE',
        ofp.OFPHFC_EPERM: 'OFPHFC_EPERM'}),
    1: ('OFPET_BAD_REQUEST', {
        ofp.OFPBRC_BAD_VERSION: 'OFPBRC_BAD_VERSION',
        ofp.OFPBRC_BAD_TYPE: 'OFPBRC_BAD_TYPE',
        ofp.OFPBRC_BAD_MULTIPART: 'OFPBRC_BAD_MULTIPART',
        ofp.OFPBRC_BAD_EXPERIMENTER: 'OFPBRC_BAD_EXPERIMENTER',
        ofp.OFPBRC_BAD_EXP_TYPE: 'OFPBRC_BAD_EXP_TYPE',
        ofp.OFPBRC_EPERM: 'OFPBRC_EPERM',
        ofp.OFPBRC_BAD_LEN: 'OFPBRC_BAD_LEN',
        ofp.OFPBRC_BUFFER_EMPTY: 'OFPBRC_BUFFER_EMPTY',
        ofp.OFPBRC_BUFFER_UNKNOWN: 'OFPBRC_BUFFER_UNKNOWN',
        ofp.OFPBRC_BAD_TABLE_ID: 'OFPBRC_BAD_TABLE_ID',
        ofp.OFPBRC_IS_SLAVE: 'OFPBRC_IS_SLAVE',
        ofp.OFPBRC_BAD_PORT: 'OFPBRC_BAD_PORT',
        ofp.OFPBRC_BAD_PACKET: 'OFPBRC_BAD_PACKET',
        ofp.OFPBRC_MULTIPART_BUFFER_OVERFLOW: 'OFPBRC_MULTIPART_BUFFER_OVERFLOW'}),
    2: ('OFPET_BAD_ACTION', {
        ofp.OFPBAC_BAD_TYPE: 'OFPBAC_BAD_TYPE',
        ofp.OFPBAC_BAD_LEN: 'OFPBAC_BAD_LEN',
        ofp.OFPBAC_BAD_EXPERIMENTER: 'OFPBAC_BAD_EXPERIMENTER',
        ofp.OFPBAC_BAD_EXP_TYPE: 'OFPBAC_BAD_EXP_TYPE',
        ofp.OFPBAC_BAD_OUT_PORT: 'OFPBAC_BAD_OUT_PORT',
        ofp.OFPBAC_BAD_ARGUMENT: 'OFPBAC_BAD_ARGUMENT',
        ofp.OFPBAC_EPERM: 'OFPBAC_EPERM',
        ofp.OFPBAC_TOO_MANY: 'OFPBAC_TOO_MANY',
        ofp.OFPBAC_BAD_QUEUE: 'OFPBAC_BAD_QUEUE',
        ofp.OFPBAC_BAD_OUT_GROUP: 'OFPBAC_BAD_OUT_GROUP',
        ofp.OFPBAC_MATCH_INCONSISTENT: 'OFPBAC_MATCH_INCONSISTENT',
        ofp.OFPBAC_UNSUPPORTED_ORDER: 'OFPBAC_UNSUPPORTED_ORDER',
        ofp.OFPBAC_BAD_TAG: 'OFPBAC_BAD_TAG',
        ofp.OFPBAC_BAD_SET_TYPE: 'OFPBAC_BAD_SET_TYPE',
        ofp.OFPBAC_BAD_SET_LEN: 'OFPBAC_BAD_SET_LEN',
        ofp.OFPBAC_BAD_SET_ARGUMENT: 'OFPBAC_BAD_SET_ARGUMENT'}),
    3: ('OFPET_BAD_INSTRUCTION', {
        ofp.OFPBIC_UNKNOWN_INST: 'OFPBIC_UNKNOWN_INST',
        ofp.OFPBIC_UNSUP_INST: 'OFPBIC_UNSUP_INST',
        ofp.OFPBIC_BAD_TABLE_ID: 'OFPBIC_BAD_TABLE_ID',
        ofp.OFPBIC_UNSUP_METADATA: 'OFPBIC_UNSUP_METADATA',
        ofp.OFPBIC_UNSUP_METADATA_MASK: 'OFPBIC_UNSUP_METADATA_MASK',
        ofp.OFPBIC_BAD_EXPERIMENTER: 'OFPBIC_BAD_EXPERIMENTER',
        ofp.OFPBIC_BAD_EXP_TYPE: 'OFPBIC_BAD_EXP_TYPE',
        ofp.OFPBIC_BAD_LEN: 'OFPBIC_BAD_LEN',
        ofp.OFPBIC_EPERM: 'OFPBIC_EPERM'}),
    4: ('OFPET_BAD_MATCH', {
        ofp.OFPBMC_BAD_TYPE: 'OFPBMC_BAD_TYPE',
        ofp.OFPBMC_BAD_LEN: 'OFPBMC_BAD_LEN',
        ofp.OFPBMC_BAD_TAG: 'OFPBMC_BAD_TAG',
        ofp.OFPBMC_BAD_DL_ADDR_MASK: 'OFPBMC_BAD_DL_ADDR_MASK',
        ofp.OFPBMC_BAD_NW_ADDR_MASK: 'OFPBMC_BAD_NW_ADDR_MASK',
        ofp.OFPBMC_BAD_WILDCARDS: 'OFPBMC_BAD_WILDCARDS',
        ofp.OFPBMC_BAD_FIELD: 'OFPBMC_BAD_FIELD',
        ofp.OFPBMC_BAD_VALUE: 'OFPBMC_BAD_VALUE',
        ofp.OFPBMC_BAD_MASK: 'OFPBMC_BAD_MASK',
        ofp.OFPBMC_BAD_PREREQ: 'OFPBMC_BAD_PREREQ',
        ofp.OFPBMC_DUP_FIELD: 'OFPBMC_DUP_FIELD',
        ofp.OFPBMC_EPERM: 'OFPBMC_EPERM'}),
    5: ('OFPET_FLOW_MOD_FAILED', {
        ofp.OFPFMFC_UNKNOWN: 'OFPFMFC_UNKNOWN',
        ofp.OFPFMFC_TABLE_FULL: 'OFPFMFC_TABLE_FULL',
        ofp.OFPFMFC_BAD_TABLE_ID: 'OFPFMFC_BAD_TABLE_ID',
        ofp.OFPFMFC_OVERLAP: 'OFPFMFC_OVERLAP',
        ofp.OFPFMFC_EPERM: 'OFPFMFC_EPERM',
        ofp.OFPFMFC_BAD_TIMEOUT: 'OFPFMFC_BAD_TIMEOUT',
        ofp.OFPFMFC_BAD_COMMAND: 'OFPFMFC_BAD_COMMAND',
        ofp.OFPFMFC_BAD_FLAGS: 'OFPFMFC_BAD_FLAGS'}),
    6: ('OFPET_GROUP_MOD_FAILED', {
        ofp.OFPGMFC_GROUP_EXISTS: 'OFPGMFC_GROUP_EXISTS',
        ofp.OFPGMFC_INVALID_GROUP: 'OFPGMFC_INVALID_GROUP',
        ofp.OFPGMFC_WEIGHT_UNSUPPORTED: 'OFPGMFC_WEIGHT_UNSUPPORTED',
        ofp.OFPGMFC_OUT_OF_GROUPS: 'OFPGMFC_OUT_OF_GROUPS',
        ofp.OFPGMFC_OUT_OF_BUCKETS: 'OFPGMFC_OUT_OF_BUCKETS',
        ofp.OFPGMFC_CHAINING_UNSUPPORTED: 'OFPGMFC_CHAINING_UNSUPPORTED',
        ofp.OFPGMFC_WATCH_UNSUPPORTED: 'OFPGMFC_WATCH_UNSUPPORTED',
        ofp.OFPGMFC_LOOP: 'OFPGMFC_LOOP',
        ofp.OFPGMFC_UNKNOWN_GROUP: 'OFPGMFC_UNKNOWN_GROUP',
        ofp.OFPGMFC_CHAINED_GROUP: 'OFPGMFC_CHAINED_GROUP',
        ofp.OFPGMFC_BAD_TYPE: 'OFPGMFC_BAD_TYPE',
        ofp.OFPGMFC_BAD_COMMAND: 'OFPGMFC_BAD_COMMAND',
        ofp.OFPGMFC_BAD_BUCKET: 'OFPGMFC_BAD_BUCKET',
        ofp.OFPGMFC_BAD_WATCH: 'OFPGMFC_BAD_WATCH',
        ofp.OFPGMFC_EPERM: 'OFPGMFC_EPERM'}),
    7: ('OFPET_PORT_MOD_FAILED', {
        ofp.OFPPMFC_BAD_PORT: 'OFPPMFC_BAD_PORT',
        ofp.OFPPMFC_BAD_HW_ADDR: 'OFPPMFC_BAD_HW_ADDR',
        ofp.OFPPMFC_BAD_CONFIG: 'OFPPMFC_BAD_CONFIG',
        ofp.OFPPMFC_BAD_ADVERTISE: 'OFPPMFC_BAD_ADVERTISE',
        ofp.OFPPMFC_EPERM: 'OFPPMFC_EPERM'}),
    8: ('OFPET_TABLE_MOD_FAILED', {
        ofp.OFPTMFC_BAD_TABLE: 'OFPTMFC_BAD_TABLE',
        ofp.OFPTMFC_BAD_CONFIG: 'OFPTMFC_BAD_CONFIG',
        ofp.OFPTMFC_EPERM: 'OFPTMFC_EPERM'}),
    9: ('OFPET_QUEUE_OP_FAILED', {
        ofp.OFPQOFC_BAD_PORT: 'OFPQOFC_BAD_PORT',
        ofp.OFPQOFC_BAD_QUEUE: 'OFPQOFC_BAD_QUEUE',
        ofp.OFPQOFC_EPERM: 'OFPQOFC_EPERM'}),
    10: ('OFPET_SWITCH_CONFIG_FAILED', {
        ofp.OFPSCFC_BAD_FLAGS: 'OFPSCFC_BAD_FLAGS',
        ofp.OFPSCFC_BAD_LEN: 'OFPSCFC_BAD_LEN',
        ofp.OFPSCFC_EPERM: 'OFPSCFC_EPERM'}),
    11: ('OFPET_ROLE_REQUEST_FAILED', {
        ofp.OFPRRFC_STALE: 'OFPRRFC_STALE',
        ofp.OFPRRFC_UNSUP: 'OFPRRFC_UNSUP',
        ofp.OFPRRFC_BAD_ROLE: 'OFPRRFC_BAD_ROLE'}),
    12: ('OFPET_METER_MOD_FAILED', {
        ofp.OFPMMFC_UNKNOWN: 'OFPMMFC_UNKNOWN',
        ofp.OFPMMFC_METER_EXISTS: 'OFPMMFC_METER_EXISTS',
        ofp.OFPMMFC_INVALID_METER: 'OFPMMFC_INVALID_METER',
        ofp.OFPMMFC_UNKNOWN_METER: 'OFPMMFC_UNKNOWN_METER',
        ofp.OFPMMFC_BAD_COMMAND: 'OFPMMFC_BAD_COMMAND',
        ofp.OFPMMFC_BAD_FLAGS: 'OFPMMFC_BAD_FLAGS',
        ofp.OFPMMFC_BAD_RATE: 'OFPMMFC_BAD_RATE',
        ofp.OFPMMFC_BAD_BURST: 'OFPMMFC_BAD_BURST',
        ofp.OFPMMFC_BAD_BAND: 'OFPMMFC_BAD_BAND',
        ofp.OFPMMFC_BAD_BAND_VALUE: 'OFPMMFC_BAD_BAND_VALUE',
        ofp.OFPMMFC_OUT_OF_METERS: 'OFPMMFC_OUT_OF_METERS',
        ofp.OFPMMFC_OUT_OF_BANDS: 'OFPMMFC_OUT_OF_BANDS'}),
    13: ('OFPET_TABLE_FEATURES_FAILED', {
        ofp.OFPTFFC_BAD_TABLE: 'OFPTFFC_BAD_TABLE',
        ofp.OFPTFFC_BAD_METADATA: 'OFPTFFC_BAD_METADATA',
        ofp.OFPTFFC_BAD_TYPE: 'OFPTFFC_BAD_TYPE',
        ofp.OFPTFFC_BAD_LEN: 'OFPTFFC_BAD_LEN',
        ofp.OFPTFFC_BAD_ARGUMENT: 'OFPTFFC_BAD_ARGUMENT',
        ofp.OFPTFFC_EPERM: 'OFPTFFC_EPERM'}),
    65535: ('OFPET_EXPERIMENTER', {}),
}


def ignore_port(port_num):
    """Return True if FAUCET should ignore this port.

    Args:
        port_num (int): switch port.
    Returns:
        bool: True if FAUCET should ignore this port.
    """
    # special case OFPP_LOCAL to allow FAUCET to manage switch admin interface.
    if port_num == ofp.OFPP_LOCAL:
        return False
    # 0xF0000000 and up are not physical ports.
    return port_num > 0xF0000000


def port_status_from_state(state):
    """Return True if OFPPS_LINK_DOWN is not set."""
    return not state & ofp.OFPPS_LINK_DOWN


def is_table_features_req(ofmsg):
    """Return True if flow message is a TFM req.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a TFM req.
    """
    return isinstance(ofmsg, parser.OFPTableFeaturesStatsRequest)


def is_flowmod(ofmsg):
    """Return True if flow message is a FlowMod.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a FlowMod
    """
    return isinstance(ofmsg, parser.OFPFlowMod)


def is_flowaddmod(ofmsg):
    """Return True if flow message is a FlowMod, add or modify.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a FlowMod, add or modify.
    """
    return isinstance(ofmsg, parser.OFPFlowMod) and ofmsg.command in (
        ofp.OFPFC_ADD, ofp.OFPFC_MODIFY, ofp.OFPFC_MODIFY_STRICT)


def is_groupmod(ofmsg):
    """Return True if OF message is a GroupMod.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a GroupMod
    """
    return isinstance(ofmsg, parser.OFPGroupMod)


def is_metermod(ofmsg):
    """Return True if OF message is a MeterMod.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a MeterMod
    """
    return isinstance(ofmsg, parser.OFPMeterMod)


def is_packetout(ofmsg):
    """Return True if OF message is a PacketOut

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a PacketOut
    """
    return isinstance(ofmsg, parser.OFPPacketOut)


def is_output(ofmsg):
    """Return True if flow message is an action output message.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a OFPActionOutput.
    """
    return isinstance(ofmsg, parser.OFPActionOutput)


def is_flowdel(ofmsg):
    """Return True if flow message is a FlowMod and a delete.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a FlowMod delete/strict.
    """
    return is_flowmod(ofmsg) and ofmsg.command in (ofp.OFPFC_DELETE, ofp.OFPFC_DELETE_STRICT)


def is_groupdel(ofmsg):
    """Return True if OF message is a GroupMod and command is delete.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a GroupMod delete
    """
    if (is_groupmod(ofmsg) and
            (ofmsg.command == ofp.OFPGC_DELETE)):
        return True
    return False


def is_meterdel(ofmsg):
    """Return True if OF message is a MeterMod and command is delete.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a MeterMod delete
    """
    if (is_metermod(ofmsg) and
            (ofmsg.command == ofp.OFPMC_DELETE)):
        return True
    return False


def is_groupadd(ofmsg):
    """Return True if OF message is a GroupMod and command is add.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a GroupMod add
    """
    if (is_groupmod(ofmsg) and
            (ofmsg.command == ofp.OFPGC_ADD)):
        return True
    return False


def is_meteradd(ofmsg):
    """Return True if OF message is a MeterMod and command is add.

    Args:
        ofmsg: ryu.ofproto.ofproto_v1_3_parser message.
    Returns:
        bool: True if is a MeterMod add
    """
    if (is_metermod(ofmsg) and
            (ofmsg.command == ofp.OFPMC_ADD)):
        return True
    return False


def is_apply_actions(instruction):
    """Return True if an apply action.

    Args:
        instruction: OpenFlow instruction.
    Returns:
        bool: True if an apply action.
    """
    return (isinstance(instruction, parser.OFPInstructionActions) and
            instruction.type == ofp.OFPIT_APPLY_ACTIONS)


def is_meter(instruction):
    """Return True if a meter.

    Args:
        instruction: OpenFlow instruction.
    Returns:
        bool: True if a meter.
    """
    return isinstance(instruction, parser.OFPInstructionMeter)


def is_set_field(action):
    return isinstance(action, parser.OFPActionSetField)


def apply_meter(meter_id):
    """Return instruction to apply a meter."""
    return parser.OFPInstructionMeter(meter_id, ofp.OFPIT_METER)


@functools.lru_cache()
def _apply_actions(actions):
    return parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)


def apply_actions(actions):
    """Return instruction that applies action list.

    Args:
        actions (list): list of OpenFlow actions.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPInstruction: instruction of actions.
    """
    return _apply_actions(tuple(actions))


@functools.lru_cache()
def goto_table(table):
    """Return instruction to goto table.

    Args:
        table (ValveTable): table to goto.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPInstruction: goto instruction.
    """
    return parser.OFPInstructionGotoTable(table.table_id)


def metadata_goto_table(metadata, mask, table):
    """Return instructions to write metadata and goto table.

    Args:
        metadata (int): metadata to write to packet
        maks (int): mask to apply to metadata
        table (ValveTable): table to goto.
    Returns:
        list of OFPInstructions"""
    return [
        parser.OFPInstructionWriteMetadata(metadata, mask),
        parser.OFPInstructionGotoTable(table.table_id)
        ]


@functools.lru_cache()
def set_field(**kwds):
    """Return action to set any field.

    Args:
        kwds (dict): exactly one field to set
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionSetField: set field action.
    """
    return parser.OFPActionSetField(**kwds)


def vid_present(vid):
    """Return VLAN VID with VID_PRESENT flag set.

    Args:
        vid (int): VLAN VID
    Returns:
        int: VLAN VID with VID_PRESENT.
    """
    return vid | ofp.OFPVID_PRESENT


def devid_present(vid):
    """Return VLAN VID without VID_PRESENT flag set.

    Args:
        vid (int): VLAN VID with VID_PRESENT.
    Returns:
        int: VLAN VID.
    """
    return vid ^ ofp.OFPVID_PRESENT


@functools.lru_cache(maxsize=1024)
def push_vlan_act(table, vlan_vid, eth_type=ether.ETH_TYPE_8021Q):
    """Return OpenFlow action list to push Ethernet 802.1Q header with VLAN VID.

    Args:
        vid (int): VLAN VID
    Returns:
        list: actions to push 802.1Q header with VLAN VID set.
    """
    return [
        parser.OFPActionPushVlan(eth_type),
        table.set_vlan_vid(vlan_vid),
    ]


@functools.lru_cache()
def dec_ip_ttl():
    """Return OpenFlow action to decrement IP TTL.

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionDecNwTtl: decrement IP TTL.
    """
    return parser.OFPActionDecNwTtl()


@functools.lru_cache(maxsize=1024)
def pop_vlan():
    """Return OpenFlow action to pop outermost Ethernet 802.1Q VLAN header.

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionPopVlan: Pop VLAN.
    """
    return parser.OFPActionPopVlan()


@functools.lru_cache(maxsize=1024)
def output_port(port_num, max_len=0):
    """Return OpenFlow action to output to a port.

    Args:
        port_num (int): port to output to.
        max_len (int): maximum length of packet to output (default no maximum).
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: output to port action.
    """
    return parser.OFPActionOutput(port_num, max_len=max_len)


def ports_from_output_port_acts(output_port_acts):
    """Return unique port numbers from OFPActionOutput actions.

    Args:
        list of ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: output to port actions.
    Returns:
        set of port number ints.
    """
    return {output_port_act.port for output_port_act in output_port_acts}


def dedupe_output_port_acts(output_port_acts):
    """Deduplicate parser.OFPActionOutputs (because Ryu doesn't define __eq__).

    Args:
        list of ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: output to port actions.
    Returns:
        list of ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: output to port actions.
    """
    output_ports = ports_from_output_port_acts(output_port_acts)
    return [output_port(port) for port in sorted(output_ports)]


@functools.lru_cache(maxsize=1024)
def output_non_output_actions(flood_acts):
    """Split output actions into deduped actions, output ports, and non-output port actions.

    Args:
        list of ryu.ofproto.ofproto_v1_3_parser.OFPActions: flood actions.
    Returns:
        set of deduped actions, output ports, and non-output actions.
    """
    output_ports = set()
    all_nonoutput_actions = set()
    deduped_acts = []
    # avoid dedupe_ofmsgs() here, as it's expensive - most of the time we are comparing
    # port numbers as integers which is much cheaper.
    for act in flood_acts:
        if is_output(act):
            if act.port in output_ports:
                continue
            output_ports.add(act.port)
        else:
            str_act = str(act)
            if str_act in all_nonoutput_actions:
                continue
            all_nonoutput_actions.add(str_act)
        deduped_acts.append(act)
    nonoutput_actions = all_nonoutput_actions - set([str(pop_vlan())])
    return (deduped_acts, output_ports, nonoutput_actions)


@functools.lru_cache()
def output_in_port():
    """Return OpenFlow action to output out input port.

    Returns:
       ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput.
    """
    return output_port(OFP_IN_PORT)


@functools.lru_cache()
def output_controller(max_len=MAX_PACKET_IN_BYTES):
    """Return OpenFlow action to packet in to the controller.

    Args:
        max_len (int): max number of bytes from packet to output.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: packet in action.
    """
    return output_port(ofp.OFPP_CONTROLLER, max_len)


def packetouts(port_nums, data):
    """Return OpenFlow action to multiply packet out to dataplane from controller.

    Args:
        port_num (list): ints, ports to output to.
        data (str): raw packet to output.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: packet out action.
    """
    random.shuffle(port_nums)
    return parser.OFPPacketOut(
        datapath=None,
        buffer_id=ofp.OFP_NO_BUFFER,
        in_port=ofp.OFPP_CONTROLLER,
        actions=[output_port(port_num) for port_num in port_nums],
        data=data)


@functools.lru_cache()
def packetout(port_num, data):
    """Return OpenFlow action to packet out to dataplane from controller.

    Args:
        port_num (int): port to output to.
        data (str): raw packet to output.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPActionOutput: packet out action.
    """
    return packetouts([port_num], data)


@functools.lru_cache()
def barrier():
    """Return OpenFlow barrier request.

    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPBarrierRequest: barrier request.
    """
    return parser.OFPBarrierRequest(None)


def table_features(body):
    return parser.OFPTableFeaturesStatsRequest(
        datapath=None, body=body)


def match(match_fields):
    """Return OpenFlow matches from dict.

    Args:
        match_fields (dict): match fields and values.
    Returns:
        ryu.ofproto.ofproto_v1_3_parser.OFPMatch: matches.
    """
    return parser.OFPMatch(**match_fields)


@functools.lru_cache()
def valve_match_vid(value):
    return to_match_vid(value, ofp.OFPVID_PRESENT)


# See 7.2.3.7 Flow Match Fields (OF 1.3.5)
MATCH_FIELDS = {
    'in_port': OFCtlUtil(ofp).ofp_port_from_user,
    'in_phy_port': str_to_int,
    'metadata': to_match_masked_int,
    'eth_dst': to_match_eth,
    'eth_src': to_match_eth,
    'eth_type': str_to_int,
    'vlan_vid': valve_match_vid,
    'vlan_pcp': str_to_int,
    'ip_dscp': str_to_int,
    'ip_ecn': str_to_int,
    'ip_proto': str_to_int,
    'ipv4_src': to_match_ip,
    'ipv4_dst': to_match_ip,
    'tcp_src': to_match_masked_int,
    'tcp_dst': to_match_masked_int,
    'udp_src': to_match_masked_int,
    'udp_dst': to_match_masked_int,
    'sctp_src': to_match_masked_int,
    'sctp_dst': to_match_masked_int,
    'icmpv4_type': str_to_int,
    'icmpv4_code': str_to_int,
    'arp_op': str_to_int,
    'arp_spa': to_match_ip,
    'arp_tpa': to_match_ip,
    'arp_sha': to_match_eth,
    'arp_tha': to_match_eth,
    'ipv6_src': to_match_ip,
    'ipv6_dst': to_match_ip,
    'ipv6_flabel': str_to_int,
    'icmpv6_type': str_to_int,
    'icmpv6_code': str_to_int,
    'ipv6_nd_target': to_match_ip,
    'ipv6_nd_sll': to_match_eth,
    'ipv6_nd_tll': to_match_eth,
    'mpls_label': str_to_int,
    'mpls_tc': str_to_int,
    'mpls_bos': str_to_int,
    'pbb_isid': to_match_masked_int,
    'tunnel_id': to_match_masked_int,
    'ipv6_exthdr': to_match_masked_int
}


def match_from_dict(match_dict):
    kwargs = {}
    for of_match, field in match_dict.items():
        of_match = OLD_MATCH_FIELDS.get(of_match, of_match)
        test_config_condition(of_match not in MATCH_FIELDS, 'Unknown match field: %s' % of_match)
        try:
            encoded_field = MATCH_FIELDS[of_match](field)
        except TypeError:
            raise InvalidConfigError('%s cannot be type %s' % (of_match, type(field)))
        kwargs[of_match] = encoded_field

    return parser.OFPMatch(**kwargs)


def _match_ip_masked(ipa):
    if isinstance(ipa, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return (str(ipa.network_address), str(ipa.netmask))
    return (str(ipa.ip), str(ipa.netmask))


@functools.lru_cache(maxsize=1024)
def build_match_dict(in_port=None, vlan=None, eth_type=None, eth_src=None,
                     eth_dst=None, eth_dst_mask=None, icmpv6_type=None,
                     nw_proto=None, nw_dst=None, metadata=None,
                     metadata_mask=None, vlan_pcp=None, udp_src=None, udp_dst=None):
    match_dict = {}
    if in_port is not None:
        match_dict['in_port'] = in_port
    if vlan is not None:
        if isinstance(vlan, int):
            vid = vlan
        else:
            vid = vlan.vid
        if vid == ofp.OFPVID_NONE:
            match_dict['vlan_vid'] = int(ofp.OFPVID_NONE)
        elif vid == ofp.OFPVID_PRESENT:
            match_dict['vlan_vid'] = (ofp.OFPVID_PRESENT, ofp.OFPVID_PRESENT)
        else:
            match_dict['vlan_vid'] = vid_present(vid)
    if eth_src is not None:
        match_dict['eth_src'] = eth_src
    if eth_dst is not None:
        if eth_dst_mask is not None:
            match_dict['eth_dst'] = (eth_dst, eth_dst_mask)
        else:
            match_dict['eth_dst'] = eth_dst
    if nw_proto is not None:
        match_dict['ip_proto'] = nw_proto
    if udp_dst is not None:
        match_dict['udp_dst'] = udp_dst
    if udp_src is not None:
        match_dict['udp_src'] = udp_src
    if icmpv6_type is not None:
        match_dict['icmpv6_type'] = icmpv6_type
    if nw_dst is not None:
        nw_dst_masked = _match_ip_masked(nw_dst)
        if eth_type == ether.ETH_TYPE_ARP:
            match_dict['arp_tpa'] = str(nw_dst.ip)
        elif eth_type == ether.ETH_TYPE_IP:
            match_dict['ipv4_dst'] = nw_dst_masked
        else:
            match_dict['ipv6_dst'] = nw_dst_masked
    if eth_type is not None:
        match_dict['eth_type'] = eth_type
    if metadata is not None:
        if metadata_mask is not None:
            match_dict['metadata'] = (metadata, metadata_mask)
        else:
            match_dict['metadata'] = metadata
    if vlan_pcp is not None:
        match_dict['vlan_pcp'] = vlan_pcp
    return match_dict


@functools.lru_cache()
def flowmod(cookie, command, table_id, priority, out_port, out_group,
            match_fields, inst, hard_timeout, idle_timeout, flags=0):
    return parser.OFPFlowMod(
        datapath=None,
        cookie=cookie,
        command=command,
        table_id=table_id,
        priority=priority,
        out_port=out_port,
        out_group=out_group,
        match=match_fields,
        instructions=inst,
        hard_timeout=hard_timeout,
        idle_timeout=idle_timeout,
        flags=flags)


def group_act(group_id):
    """Return an action to run a group."""
    return parser.OFPActionGroup(group_id)


def bucket(weight=0, watch_port=ofp.OFPP_ANY,
           watch_group=ofp.OFPG_ANY, actions=None):
    """Return a group action bucket with provided actions."""
    return parser.OFPBucket(
        weight=weight,
        watch_port=watch_port,
        watch_group=watch_group,
        actions=actions)


def build_group_flood_buckets(vlan_flood_acts):
    """Return a list of group buckets to implement flooding on a VLAN."""
    buckets = []
    non_outputs = []
    for act in vlan_flood_acts:
        if is_output(act):
            buckets.append(bucket(actions=non_outputs+[act]))
        else:
            non_outputs.append(act)
    return buckets


def groupmod(datapath=None, type_=ofp.OFPGT_ALL, group_id=0, buckets=None):
    """Modify a group."""
    return parser.OFPGroupMod(
        datapath,
        ofp.OFPGC_MODIFY,
        type_,
        group_id,
        buckets)


def groupmod_ff(datapath=None, group_id=0, buckets=None):
    """Modify a fast failover group."""
    return groupmod(datapath, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)


def groupadd(datapath=None, type_=ofp.OFPGT_ALL, group_id=0, buckets=None):
    """Add a group."""
    return parser.OFPGroupMod(
        datapath,
        ofp.OFPGC_ADD,
        type_,
        group_id,
        buckets)


def groupadd_ff(datapath=None, group_id=0, buckets=None):
    """Add a fast failover group."""
    return groupadd(datapath, type_=ofp.OFPGT_FF, group_id=group_id, buckets=buckets)


def groupdel(datapath=None, group_id=ofp.OFPG_ALL):
    """Delete a group (default all groups)."""
    return parser.OFPGroupMod(
        datapath,
        ofp.OFPGC_DELETE,
        0,
        group_id)


def meterdel(datapath=None, meter_id=ofp.OFPM_ALL):
    """Delete a meter (default all meters)."""
    return parser.OFPMeterMod(
        datapath,
        ofp.OFPMC_DELETE,
        0,
        meter_id)


def meteradd(meter_conf, command=ofp.OFPMC_ADD):
    """Add a meter based on YAML configuration."""

    class NoopDP:
        """Fake DP to be able to use ofctl to parse meter config."""

        id = 0
        msg = None
        ofproto = ofp
        ofproto_parser = parser

        def send_msg(self, msg):
            """Save msg only."""
            self.msg = msg

        @staticmethod
        def set_xid(msg):
            """Clear msg XID."""
            msg.xid = 0

    noop_dp = NoopDP()
    ofctl.mod_meter_entry(noop_dp, meter_conf, command)
    noop_dp.msg.xid = None
    noop_dp.msg.datapath = None
    return noop_dp.msg


def controller_pps_meteradd(datapath=None, pps=0):
    """Add a PPS meter towards controller."""
    return parser.OFPMeterMod(
        datapath=datapath,
        command=ofp.OFPMC_ADD,
        flags=ofp.OFPMF_PKTPS,
        meter_id=ofp.OFPM_CONTROLLER,
        bands=[parser.OFPMeterBandDrop(rate=pps)])


def controller_pps_meterdel(datapath=None):
    """Delete a PPS meter towards controller."""
    return parser.OFPMeterMod(
        datapath=datapath,
        command=ofp.OFPMC_DELETE,
        flags=ofp.OFPMF_PKTPS,
        meter_id=ofp.OFPM_CONTROLLER)


def slowpath_pps_meteradd(datapath=None, pps=0):
    """Add a PPS meter towards controller."""
    return parser.OFPMeterMod(
        datapath=datapath,
        command=ofp.OFPMC_ADD,
        flags=ofp.OFPMF_PKTPS,
        meter_id=ofp.OFPM_SLOWPATH,
        bands=[parser.OFPMeterBandDrop(rate=pps)])


def slowpath_pps_meterdel(datapath=None):
    """Delete a PPS meter towards controller."""
    return parser.OFPMeterMod(
        datapath=datapath,
        command=ofp.OFPMC_DELETE,
        flags=ofp.OFPMF_PKTPS,
        meter_id=ofp.OFPM_SLOWPATH)


def is_global_flowdel(ofmsg):
    """Is a delete of all flows in all tables."""
    return is_flowdel(ofmsg) and ofmsg.table_id == ofp.OFPTT_ALL and not ofmsg.match.items()


def is_global_groupdel(ofmsg):
    """Is a delete of all groups."""
    return is_groupdel(ofmsg) and ofmsg.group_id == ofp.OFPG_ALL


def is_global_meterdel(ofmsg):
    """Is a delete of all meters."""
    return is_meterdel(ofmsg) and ofmsg.meter_id == ofp.OFPM_ALL


# We can tell right away what kind of OF messages these are.
_MSG_KINDS_TYPES = {
    parser.OFPPacketOut: 'packetout',
    parser.OFPTableFeaturesStatsRequest: 'tfm',
    parser.OFPSetConfig: 'config',
    parser.OFPSetAsync: 'config',
    parser.OFPDescStatsRequest: 'config',
}


# We need to examine the OF message more closely to classify it.
_MSG_KINDS = {
    parser.OFPFlowMod: (
        ('deleteglobal', is_global_flowdel), ('delete', is_flowdel), ('flowaddmod', is_flowaddmod)),
    parser.OFPGroupMod: (
        ('deleteglobal', is_global_groupdel), ('delete', is_groupdel), ('groupadd', is_groupadd)),
    parser.OFPMeterMod: (
        ('deleteglobal', is_global_meterdel), ('delete', is_meterdel), ('meteradd', is_meteradd)),
}


def _msg_kind(ofmsg):
    ofmsg_type = type(ofmsg)
    ofmsg_kind = _MSG_KINDS_TYPES.get(ofmsg_type, None)
    if ofmsg_kind:
        return ofmsg_kind
    kinds = _MSG_KINDS.get(ofmsg_type, None)
    if kinds:
        for kind, kind_func in kinds:
            if kind_func(ofmsg):
                return kind
    return 'other'


def _partition_ofmsgs(input_ofmsgs):
    """Partition input ofmsgs by kind."""
    by_kind = {}
    for ofmsg in input_ofmsgs:
        by_kind.setdefault(_msg_kind(ofmsg), []).append(ofmsg)
    return by_kind


def _flowmodkey(ofmsg):
    return (ofmsg.match, ofmsg.cookie, ofmsg.priority, ofmsg.table_id)


def dedupe_ofmsgs(input_ofmsgs, random_order, flowkey):
    """Return deduplicated ofmsg list."""
    # Built in comparison doesn't work until serialized() called
    # Can't use dict or json comparison as may be nested
    deduped_input_ofmsgs = {flowkey(ofmsg): ofmsg for ofmsg in input_ofmsgs}
    if random_order:
        ofmsgs = list(deduped_input_ofmsgs.values())
        random.shuffle(ofmsgs)
        return ofmsgs
    # If priority present, send highest table ID/priority first.
    return sorted(
        deduped_input_ofmsgs.values(),
        key=lambda ofmsg: (
            getattr(ofmsg, 'table_id', ofp.OFPTT_ALL), getattr(ofmsg, 'priority', 2**16+1)), reverse=True)


def dedupe_overlaps_ofmsgs(input_ofmsgs, random_order, flowkey):
    deduped_ofmsgs = dedupe_ofmsgs(input_ofmsgs, random_order, flowkey)
    ofmsgs_by_table = {}
    for ofmsg in deduped_ofmsgs:
        table_id = getattr(ofmsg, 'table_id', None)
        ofmsgs_by_table.setdefault(table_id, []).append(ofmsg)
    all_table_ids = {table_id for table_id in ofmsgs_by_table if isinstance(table_id, int)}

    # If priority-less deletes across all tables are detected, then remove any
    # overlapping deletes (e.g. if a delete all tables vlan=100 is deleted, then remove
    # all other table-specific deletes that have vlan=100).
    if ofp.OFPTT_ALL in all_table_ids:
        overlap_matches = {
            tuple(ofmsg.match.items()) for ofmsg in ofmsgs_by_table[ofp.OFPTT_ALL]
            if not ofmsg.priority}
        table_ids = all_table_ids - {ofp.OFPTT_ALL}
        if overlap_matches and table_ids:
            for table_id in table_ids:
                for overlap_match in overlap_matches:
                    overlap_match = set(overlap_match)
                    ofmsgs_by_table[table_id] = [
                        ofmsg for ofmsg in ofmsgs_by_table[table_id]
                        if not overlap_match.issubset(set(ofmsg.match.items()))]
            nooverlaps_ofmsgs = []
            for _, ofmsgs in sorted(ofmsgs_by_table.items(), reverse=True):
                nooverlaps_ofmsgs.extend(ofmsgs)
            return nooverlaps_ofmsgs

    return deduped_ofmsgs



# kind, random_order, suggest_barrier, flowkey
_OFMSG_ORDER = (
    ('config', False, True, str, dedupe_ofmsgs),
    ('deleteglobal', False, True, str, dedupe_ofmsgs),
    ('delete', False, True, str, dedupe_overlaps_ofmsgs),
    ('tfm', False, True, str, dedupe_ofmsgs),
    ('groupadd', False, True, str, dedupe_ofmsgs),
    ('meteradd', False, True, str, dedupe_ofmsgs),
    ('flowaddmod', False, False, _flowmodkey, dedupe_ofmsgs),
    ('other', False, False, str, dedupe_ofmsgs),
    ('packetout', True, False, str, dedupe_ofmsgs),
)


def valve_flowreorder(input_ofmsgs, use_barriers=True):
    """Reorder flows for better OFA performance."""
    # Move all deletes to be first, and add one barrier,
    # while optionally randomizing order. Platforms that do
    # parallel delete will perform better and platforms that
    # don't will have at most only one barrier to deal with.
    output_ofmsgs = []
    by_kind = _partition_ofmsgs(input_ofmsgs)

    # Suppress all other relevant deletes if a global delete is present.
    delete_global_ofmsgs = by_kind.get('deleteglobal', [])
    if delete_global_ofmsgs:
        global_types = {type(ofmsg) for ofmsg in delete_global_ofmsgs}
        new_delete = [ofmsg for ofmsg in by_kind.get('delete', []) if type(ofmsg) not in global_types]
        by_kind['delete'] = new_delete

    for kind, random_order, suggest_barrier, flowkey, dedupe_func in _OFMSG_ORDER:
        ofmsgs = dedupe_func(by_kind.get(kind, []), random_order, flowkey)
        if ofmsgs:
            output_ofmsgs.extend(ofmsgs)
            if use_barriers and suggest_barrier:
                output_ofmsgs.append(barrier())
    return output_ofmsgs


def flood_tagged_port_outputs(ports, in_port=None, exclude_ports=None):
    """Return list of actions necessary to flood to list of tagged ports."""
    flood_acts = []
    in_port_mirror_output_ports = {}
    if in_port is not None:
        in_port_mirror_output_ports = ports_from_output_port_acts(in_port.mirror_actions())
    if ports:
        for port in ports:
            if in_port is not None and port == in_port:
                if in_port.hairpin:
                    flood_acts.append(output_in_port())
                continue
            if exclude_ports and port in exclude_ports:
                continue
            flood_acts.append(output_port(port.number))
            # Only mirror if different mirror actions to in_port (already will be mirrored on input).
            mirror_actions = port.mirror_actions()
            mirror_output_ports = ports_from_output_port_acts(mirror_actions)
            if in_port is None or in_port_mirror_output_ports != mirror_output_ports:
                flood_acts.extend(mirror_actions)
    return dedupe_output_port_acts(flood_acts)


def flood_untagged_port_outputs(ports, in_port=None, exclude_ports=None):
    """Return list of actions necessary to flood to list of untagged ports."""
    flood_acts = flood_tagged_port_outputs(
        ports, in_port=in_port, exclude_ports=exclude_ports)
    if flood_acts:
        flood_acts = [pop_vlan()] + flood_acts
    return flood_acts


def flood_port_outputs(tagged_ports, untagged_ports, in_port=None, exclude_ports=None):
    """Return actions for both tagged and untagged ports."""
    return (
        flood_tagged_port_outputs(tagged_ports, in_port, exclude_ports) +
        flood_untagged_port_outputs(untagged_ports, in_port, exclude_ports))


def faucet_config(datapath=None):
    """Return switch config for FAUCET."""
    return parser.OFPSetConfig(datapath, ofp.OFPC_FRAG_NORMAL, 0)


def faucet_async(datapath=None, notify_flow_removed=False, packet_in=True, port_status=True):
    """Return async message config for FAUCET/Gauge"""
    packet_in_mask = 0
    if packet_in:
        packet_in_mask = 1 << ofp.OFPR_ACTION
    port_status_mask = 0
    if port_status:
        port_status_mask = (
            1 << ofp.OFPPR_ADD | 1 << ofp.OFPPR_DELETE | 1 << ofp.OFPPR_MODIFY)
    flow_removed_mask = 0
    if notify_flow_removed:
        flow_removed_mask = (
            1 << ofp.OFPRR_IDLE_TIMEOUT | 1 << ofp.OFPRR_HARD_TIMEOUT)
    return parser.OFPSetAsync(
        datapath,
        [packet_in_mask, packet_in_mask],
        [port_status_mask, port_status_mask],
        [flow_removed_mask, flow_removed_mask])


def desc_stats_request(datapath=None):
    """Query switch description."""
    return parser.OFPDescStatsRequest(datapath, 0)
