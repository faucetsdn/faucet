#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve.py."""

# pylint: disable=too-many-lines

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
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


from functools import partial
import copy
import hashlib
import os
import unittest
import time

from os_ken.ofproto import ofproto_v1_3 as ofp

from faucet import config_parser
from faucet import config_parser_util
from faucet import valve_acl
from faucet import valve_of

from clib.fakeoftable import CONTROLLER_PORT
from clib.valve_test_lib import (
    BASE_DP1_CONFIG,
    CONFIG,
    DP1_CONFIG,
    FAUCET_MAC,
    ValveTestBases,
)


class ValveIncludeTestCase(ValveTestBases.ValveTestNetwork):
    """Test include optional files."""

    CONFIG = (
        """
include-optional: ['/does/not/exist/']
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup config with non-existent optional include file"""
        self.setup_valves(self.CONFIG)

    def test_include_optional(self):
        """Test include optional files."""
        self.assertEqual(1, int(self.get_prom("dp_status")))


class ValveBadConfTestCase(ValveTestBases.ValveTestNetwork):
    """Test recovery from a bad config file."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    MORE_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    BAD_CONFIG = """
dps: {}
"""

    def setUp(self):
        """Setup invalid config"""
        self.setup_valves(self.CONFIG)

    def test_bad_conf(self):
        """Test various config types & config reloading"""
        for config, load_error in (
            (self.CONFIG, 0),
            (self.BAD_CONFIG, 1),
            (self.CONFIG, 0),
            (self.MORE_CONFIG, 0),
            (self.BAD_CONFIG, 1),
            (self.CONFIG, 0),
        ):
            with open(self.config_file, "w", encoding="utf-8") as config_file:
                config_file.write(config)
            self.valves_manager.request_reload_configs(
                self.mock_time(), self.config_file
            )
            self.assertEqual(
                load_error,
                self.get_prom("faucet_config_load_error", bare=True),
                msg="%u: %s" % (load_error, config),
            )


class ValveChangeVLANACLTestCase(ValveTestBases.ValveTestNetwork):
    CONFIG = (
        """
acls:
  acl1:
  - rule:
      eth_type: 0x0806
      actions:
        allow: 1
vlans:
  vlan1:
    acls_in:
    - acl1
    vid: 10
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
"""
        % DP1_CONFIG
    )

    MORE_CONFIG = (
        """
acls:
  acl1:
  - rule:
      eth_type: 0x0806
      actions:
        allow: 1
  - rule:
      eth_type: 0x0800
      actions:
        allow: 0
vlans:
  vlan1:
    acls_in:
    - acl1
    vid: 10
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: vlan1
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_change_vlan_acl(self):
        """Test vlan ACL change is detected."""
        self.update_and_revert_config(self.CONFIG, self.MORE_CONFIG, "warm")


class ValveRemovePortAclWarmStartTestCase(ValveTestBases.ValveTestNetwork):
    """Removing all ACLs from a port warm-restarts and clears the
    per-port ACL flows (no stale block-ping flow remaining)."""

    CONFIG = (
        """
acls:
    block-ping:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
vlans:
    office:
        vid: 100
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
                acls_in: [block-ping]
            2:
                native_vlan: office
                acls_in: [block-ping]
"""
        % DP1_CONFIG
    )

    REMOVE_ACL_CONFIG = (
        """
acls:
    block-ping:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
vlans:
    office:
        vid: 100
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
                acls_in: [block-ping]
            2:
                native_vlan: office
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Set up DP with two ports, both with the same port-level ACL."""
        self.setup_valves(self.CONFIG)

    def _port_acl_table_flows(self, port_num):
        """Return all flows in port_acl_table that match in_port=port_num."""
        valve = self.valves_manager.valves[self.DP_ID]
        port_acl_table_id = valve.acl_manager.port_acl_table.table_id
        ftes = self.network.tables[self.DP_ID].tables[port_acl_table_id]
        results = []
        for fte in ftes:
            in_port_bits = fte.match_values.get("in_port")
            if in_port_bits is None:
                continue
            try:
                if int(in_port_bits.bin, 2) == port_num:
                    results.append(fte)
            except (AttributeError, ValueError):
                pass
        return results

    def test_remove_port_acl(self):
        """Removing port 2's ACL leaves no stale block-ping flow."""
        port2_flows = self._port_acl_table_flows(2)
        self.assertTrue(
            any(
                flow.match_values.get("ip_proto") is not None
                and int(flow.match_values["ip_proto"].bin, 2) == 1
                for flow in port2_flows
            ),
            "block-ping flow not present on port 2 before reload",
        )

        self.update_config(self.REMOVE_ACL_CONFIG, reload_type="warm")

        port2_flows = self._port_acl_table_flows(2)
        for flow in port2_flows:
            ip_proto_bits = flow.match_values.get("ip_proto")
            if ip_proto_bits is None:
                continue
            self.assertNotEqual(
                int(ip_proto_bits.bin, 2),
                1,
                "stale block-ping flow remains on port 2 after warm reload: %s" % flow,
            )


class ValveAddPortAclToBarePortTestCase(ValveTestBases.ValveTestNetwork):
    """Adding an ACL to a previously-bare port must warm-restart and
    replace the default goto-vlan flow with the new ACL's flow."""

    CONFIG = (
        """
acls:
    block-ping:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
vlans:
    office:
        vid: 100
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
                acls_in: [block-ping]
            2:
                native_vlan: office
"""
        % DP1_CONFIG
    )

    ADD_ACL_CONFIG = (
        """
acls:
    block-ping:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
vlans:
    office:
        vid: 100
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
                acls_in: [block-ping]
            2:
                native_vlan: office
                acls_in: [block-ping]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Set up DP where port 1 has an ACL and port 2 does not."""
        self.setup_valves(self.CONFIG)

    def test_add_port_acl(self):
        """Adding an ACL to a previously-bare port warm-restarts cleanly."""
        self.update_and_revert_config(self.CONFIG, self.ADD_ACL_CONFIG, "warm")


class ValveDiffAddmodsGroupModTestCase(unittest.TestCase):
    """diff_addmods must tolerate OFPGroupMod entries in the addmod
    list (produced by ACL rules with `failover` actions) instead of
    AttributeError on .match / .cookie / etc. Group mods pass through
    on the add side; old-side group mods are dropped."""

    def test_groupmod_passthrough(self):
        from os_ken.ofproto import (
            ofproto_v1_3_parser as parser,
        )  # pylint: disable=import-outside-toplevel

        bucket = parser.OFPBucket(watch_port=1, actions=[parser.OFPActionOutput(1)])
        group_add = parser.OFPGroupMod(
            datapath=None,
            command=ofp.OFPGC_ADD,
            type_=ofp.OFPGT_FF,
            group_id=42,
            buckets=[bucket],
        )
        flow_add = parser.OFPFlowMod(
            datapath=None,
            cookie=0,
            command=ofp.OFPFC_ADD,
            table_id=0,
            priority=100,
            match=parser.OFPMatch(eth_type=0x800),
            instructions=[],
        )

        dels, adds = valve_acl.diff_addmods(
            lambda _tid: None,
            old_addmods=[group_add, flow_add],
            new_addmods=[group_add, flow_add],
        )
        # The group_add on new side flows through as an add; old side dropped.
        self.assertIn(group_add, adds, "group mod should pass through as add")
        self.assertEqual(
            [],
            dels,
            "no flowdels expected when old and new are identical flows",
        )


class ValveGranularPortAclWarmReloadTestCase(ValveTestBases.ValveTestNetwork):
    """Editing a single ACL rule emits one flowdel for the changed
    rule's old form plus one flowmod for the new form. Unchanged rules
    emit nothing (diff_addmods skips matching keys)."""

    CONFIG = (
        """
acls:
    multi-rule:
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 80
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 443
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
                acls_in: [multi-rule]
"""
        % DP1_CONFIG
    )

    NEW_CONFIG = (
        """
acls:
    multi-rule:
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 80
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 8080
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
                acls_in: [multi-rule]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Set up DP with a port carrying a 4-rule ACL."""
        self.setup_valves(self.CONFIG)

    def test_granular_emits_old_dels_and_new_adds(self):
        """Editing rule 2 emits exactly 1 flowdel for old rule 2 and 1
        flowmod for new rule 2. Unchanged rules (tcp_dst=80, ip_proto=1,
        default) emit nothing on either side -- the diff key for an
        unchanged rule is identical between old and new addmod lists,
        so diff_addmods skips it."""
        valve = self.valves_manager.valves[self.DP_ID]
        port_acl_table_id = valve.acl_manager.port_acl_table.table_id

        self.update_config(self.NEW_CONFIG, reload_type="warm")

        sent = self.last_flows_to_dp[self.DP_ID]
        port_acl_msgs = [
            msg
            for msg in sent
            if hasattr(msg, "table_id") and msg.table_id == port_acl_table_id
        ]
        old_rule2_dels = [
            m
            for m in port_acl_msgs
            if m.command == ofp.OFPFC_DELETE_STRICT
            and dict(m.match.items()).get("tcp_dst") == 443
        ]
        new_rule2_adds = [
            m
            for m in port_acl_msgs
            if m.command == ofp.OFPFC_ADD
            and dict(m.match.items()).get("tcp_dst") == 8080
        ]
        self.assertEqual(
            1,
            len(old_rule2_dels),
            "expected exactly 1 flowdel for old rule 2 (tcp_dst=443)",
        )
        self.assertEqual(
            1,
            len(new_rule2_adds),
            "expected exactly 1 flowmod for new rule 2 (tcp_dst=8080)",
        )

        # Unchanged rules: no flowmods or flowdels should reference them.
        for unchanged_match in (
            {"tcp_dst": 80},
            {"ip_proto": 1, "tcp_dst": None},
        ):
            for msg in port_acl_msgs:
                msg_match = dict(msg.match.items())
                if "tcp_dst" in unchanged_match and unchanged_match["tcp_dst"] is None:
                    if msg_match.get("ip_proto") == 1 and "tcp_dst" not in msg_match:
                        self.fail(
                            "unchanged ICMP rule emitted a flowmod/flowdel: %s" % msg
                        )
                elif msg_match.get("tcp_dst") == unchanged_match.get("tcp_dst"):
                    self.fail(
                        "unchanged rule (tcp_dst=%s) emitted a "
                        "flowmod/flowdel: %s" % (unchanged_match["tcp_dst"], msg)
                    )

    def test_granular_reload_emits_only_delta(self):
        """A 1-rule edit in a 4-rule ACL emits exactly 2 ofmsgs (1 del +
        1 add) regardless of N. This property is what makes granular
        reload viable for VLANs that carry hundreds of ACL rules: cost
        scales with k (rules changed), not N (rules total)."""
        valve = self.valves_manager.valves[self.DP_ID]
        port_acl_table_id = valve.acl_manager.port_acl_table.table_id

        self.update_config(self.NEW_CONFIG, reload_type="warm")

        sent = self.last_flows_to_dp[self.DP_ID]
        port_acl_msgs = [
            msg
            for msg in sent
            if hasattr(msg, "table_id") and msg.table_id == port_acl_table_id
        ]
        self.assertEqual(
            2,
            len(port_acl_msgs),
            "diff_addmods should emit exactly 1 del + 1 add for a "
            "1-rule edit; got %d port_acl ofmsgs: %s"
            % (len(port_acl_msgs), port_acl_msgs),
        )


class ValveAclActionOnlyChangeWarmReloadTestCase(ValveTestBases.ValveTestNetwork):
    """When an ACL rule's match is unchanged but its action flips
    (e.g. allow:0 -> allow:1), granular reload must still emit a
    flowdel for the old form and a flowmod for the new. The diff key
    must include instructions; otherwise the rule is mistakenly
    considered unchanged and the old action stays on the wire.
    Regression for FaucetStringOfDPACLOverrideTest."""

    CONFIG = (
        """
acls:
    override:
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
                acls_in: [override]
"""
        % DP1_CONFIG
    )

    NEW_CONFIG = (
        """
acls:
    override:
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
            actions:
                allow: 1
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
                acls_in: [override]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Set up DP with a port-level ACL that blocks tcp_dst=5001."""
        self.setup_valves(self.CONFIG)

    def _tcp_dst_5001_inst(self):
        """Return the instructions installed in port_acl_table for the
        flow matching tcp_dst=5001. None if no such flow exists."""
        valve = self.valves_manager.valves[self.DP_ID]
        port_acl_table_id = valve.acl_manager.port_acl_table.table_id
        ftes = self.network.tables[self.DP_ID].tables[port_acl_table_id]
        for fte in ftes:
            tcp_dst_bits = fte.match_values.get("tcp_dst")
            if tcp_dst_bits is None:
                continue
            try:
                if int(tcp_dst_bits.bin, 2) == 5001:
                    return fte.instructions
            except (AttributeError, ValueError):
                pass
        return None

    def test_action_flip_takes_effect(self):
        """The blocked rule (allow:0) installs no goto/apply-action
        instructions; the allow rule (allow:1) installs at least one
        instruction. After flipping the action, the on-wire flow's
        instructions must reflect the NEW action -- otherwise the
        granular reload silently kept the old action."""
        before_inst = self._tcp_dst_5001_inst()
        self.assertIsNotNone(before_inst, "blocked rule flow not installed")
        before_inst_count = len(before_inst)

        self.update_config(self.NEW_CONFIG, reload_type="warm")

        after_inst = self._tcp_dst_5001_inst()
        self.assertIsNotNone(after_inst, "rule flow disappeared after granular reload")
        self.assertGreater(
            len(after_inst),
            before_inst_count,
            "action flip allow:0 -> allow:1 did not change instructions; "
            "granular reload missed the action change",
        )

    def test_action_flip_emits_one_add(self):
        """Action-only change must emit exactly one OFPFC_ADD for the
        changed rule's match -- the new rule's flowmod."""
        valve = self.valves_manager.valves[self.DP_ID]
        port_acl_table_id = valve.acl_manager.port_acl_table.table_id

        self.update_config(self.NEW_CONFIG, reload_type="warm")

        sent = self.last_flows_to_dp[self.DP_ID]
        adds_for_5001 = [
            msg
            for msg in sent
            if hasattr(msg, "table_id")
            and msg.table_id == port_acl_table_id
            and msg.command == ofp.OFPFC_ADD
            and dict(msg.match.items()).get("tcp_dst") == 5001
        ]
        self.assertEqual(
            1,
            len(adds_for_5001),
            "expected 1 flowmod for new action; got %d" % len(adds_for_5001),
        )


class ValveCombinedVlanAclAndConfigChangeTestCase(ValveTestBases.ValveTestNetwork):
    """A VLAN with both ACL and non-ACL changes takes the heavy
    reinstall path; granular ACL is skipped to avoid double-writing."""

    CONFIG = (
        """
acls:
    block-ping:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
vlans:
    office:
        vid: 100
        description: "old"
        acls_in: [block-ping]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
"""
        % DP1_CONFIG
    )

    NEW_CONFIG = (
        """
acls:
    block-ping:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            ip_proto: 6
            actions:
                allow: 1
vlans:
    office:
        vid: 100
        description: "new"
        acls_in: [block-ping]
        unicast_flood: false
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Set up DP with one VLAN carrying an ACL."""
        self.setup_valves(self.CONFIG)

    def test_combined_change_takes_heavy_path(self):
        """ACL+config combined VLAN change still warm-restarts cleanly."""
        self.update_and_revert_config(self.CONFIG, self.NEW_CONFIG, "warm")


class ValveVlanAclEgressChangeTestCase(ValveTestBases.ValveTestNetwork):
    """Granular warm reload must handle VLAN egress ACL changes
    (acls_out) the same as ingress (acls_in)."""

    CONFIG = (
        """
acls:
    egress-block:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
        acls_out: [egress-block]
dps:
    s1:
%s
        egress_pipeline: True
        interfaces:
            1:
                native_vlan: office
"""
        % DP1_CONFIG
    )

    NEW_CONFIG = (
        """
acls:
    egress-block:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            ip_proto: 17
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
        acls_out: [egress-block]
dps:
    s1:
%s
        egress_pipeline: True
        interfaces:
            1:
                native_vlan: office
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Set up DP with VLAN egress ACL configured."""
        self.setup_valves(self.CONFIG)

    def _egress_acl_flows_with_ip_proto(self, ip_proto):
        valve = self.valves_manager.valves[self.DP_ID]
        egress_table_id = valve.acl_manager.egress_acl_table.table_id
        ftes = self.network.tables[self.DP_ID].tables[egress_table_id]
        results = []
        for fte in ftes:
            ip_proto_bits = fte.match_values.get("ip_proto")
            if ip_proto_bits is None:
                continue
            try:
                if int(ip_proto_bits.bin, 2) == ip_proto:
                    results.append(fte)
            except (AttributeError, ValueError):
                pass
        return results

    def test_egress_acl_change(self):
        """Editing rules of a VLAN egress ACL is warm-restartable."""
        self.update_and_revert_config(self.CONFIG, self.NEW_CONFIG, "warm")

    def test_egress_acl_new_rule_lands_in_egress_table(self):
        """After adding a UDP-drop rule, the egress ACL table holds both
        the unchanged ICMP flow and the new UDP flow."""
        self.assertTrue(
            self._egress_acl_flows_with_ip_proto(1),
            "ICMP egress flow not present before reload",
        )
        self.assertFalse(
            self._egress_acl_flows_with_ip_proto(17),
            "UDP egress flow already present before reload",
        )

        self.update_config(self.NEW_CONFIG, reload_type="warm")

        self.assertTrue(
            self._egress_acl_flows_with_ip_proto(1),
            "ICMP egress flow disappeared after granular warm reload",
        )
        self.assertTrue(
            self._egress_acl_flows_with_ip_proto(17),
            "UDP egress flow not installed after granular warm reload",
        )


class ValveVlanAclRuleRemovedWarmReloadTestCase(ValveTestBases.ValveTestNetwork):
    """Granular VLAN ACL reload removes flows for rules dropped from
    the new ACL -- not just additive. Symmetric to
    ValveRemovePortAclWarmStartTestCase but for VLAN ACLs."""

    CONFIG = (
        """
acls:
    multi-rule:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
        - rule:
            dl_type: 0x806
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
        acls_in: [multi-rule]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
"""
        % DP1_CONFIG
    )

    NEW_CONFIG = (
        """
acls:
    multi-rule:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
vlans:
    office:
        vid: 100
        acls_in: [multi-rule]
dps:
    s1:
%s
        interfaces:
            1:
                native_vlan: office
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Set up DP with a VLAN ACL containing an ARP-drop rule."""
        self.setup_valves(self.CONFIG)

    def _vlan_acl_flows_with_dl_type(self, dl_type):
        valve = self.valves_manager.valves[self.DP_ID]
        vlan_acl_table_id = valve.acl_manager.vlan_acl_table.table_id
        ftes = self.network.tables[self.DP_ID].tables[vlan_acl_table_id]
        results = []
        for fte in ftes:
            eth_type_bits = fte.match_values.get("eth_type")
            if eth_type_bits is None:
                continue
            try:
                if int(eth_type_bits.bin, 2) == dl_type:
                    results.append(fte)
            except (AttributeError, ValueError):
                pass
        return results

    def test_removed_rule_flow_disappears(self):
        """Dropping the ARP rule from the VLAN ACL must clear the
        corresponding flow from vlan_acl_table; the ICMP rule stays."""
        self.assertTrue(
            self._vlan_acl_flows_with_dl_type(0x806),
            "ARP rule's flow not present before reload",
        )
        self.assertTrue(
            self._vlan_acl_flows_with_dl_type(0x800),
            "ICMP rule's flow not present before reload",
        )

        self.update_config(self.NEW_CONFIG, reload_type="warm")

        self.assertFalse(
            self._vlan_acl_flows_with_dl_type(0x806),
            "stale ARP rule flow remains in vlan_acl_table after granular reload",
        )
        self.assertTrue(
            self._vlan_acl_flows_with_dl_type(0x800),
            "ICMP rule's flow disappeared after granular reload "
            "(should be unchanged)",
        )


class ValveChangePortTestCase(ValveTestBases.ValveTestNetwork):
    """Test changes to config on ports."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
                permanent_learn: True
"""
        % DP1_CONFIG
    )

    LESS_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
                permanent_learn: False
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_delete_permanent_learn(self):
        """Test port permanent learn can deconfigured."""
        table = self.network.tables[self.DP_ID]
        before_table_state = table.table_state()
        self.rcv_packet(
            2,
            0x200,
            {
                "eth_src": self.P2_V200_MAC,
                "eth_dst": self.P3_V200_MAC,
                "ipv4_src": "10.0.0.2",
                "ipv4_dst": "10.0.0.3",
                "vid": 0x200,
            },
        )
        self.update_and_revert_config(
            self.CONFIG,
            self.LESS_CONFIG,
            "warm",
            before_table_states={self.DP_ID: before_table_state},
        )


class ValveDeletePortTestCase(ValveTestBases.ValveTestNetwork):
    """Test deletion of a port."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    LESS_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_port_delete(self):
        """Test port can be deleted."""
        self.update_and_revert_config(self.CONFIG, self.LESS_CONFIG, "cold")


class ValveAddPortMirrorNoDelVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test addition of port mirroring does not cause a del VLAN."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                output_only: true
"""
        % DP1_CONFIG
    )

    MORE_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                output_only: true
                mirror: [1]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        _ = self.setup_valves(self.CONFIG)[self.DP_ID]

    def test_port_mirror(self):
        """Test addition of port mirroring is a warm start."""
        _ = self.update_config(self.MORE_CONFIG, reload_type="warm")[self.DP_ID]


class ValveAddPortTestCase(ValveTestBases.ValveTestNetwork):
    """Test addition of a port."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    MORE_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    @staticmethod
    def _inport_flows(in_port, ofmsgs):
        return [
            ofmsg
            for ofmsg in ValveTestBases.flowmods_from_flows(ofmsgs)
            if ofmsg.match.get("in_port") == in_port
        ]

    def setUp(self):
        """Setup basic port and vlan config"""
        initial_ofmsgs = self.setup_valves(self.CONFIG)[self.DP_ID]
        self.assertFalse(self._inport_flows(3, initial_ofmsgs))

    def test_port_add(self):
        """Test port can be added."""
        reload_ofmsgs = self.update_config(self.MORE_CONFIG, reload_type="cold")[
            self.DP_ID
        ]
        self.assertTrue(self._inport_flows(3, reload_ofmsgs))


class ValveAddPortTrafficTestCase(ValveTestBases.ValveTestNetwork):
    """Test addition of a port with traffic."""

    # NOTE: This needs to use 'Generic' hardware,
    #  as GenericTFM does not support 'warm' start
    REQUIRE_TFM = False

    CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: Generic
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
"""

    MORE_CONFIG = """
dps:
    s1:
        dp_id: 1
        hardware: Generic
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                tagged_vlans: [0x100]
"""

    @staticmethod
    def _inport_flows(in_port, ofmsgs):
        return [
            ofmsg
            for ofmsg in ValveTestBases.flowmods_from_flows(ofmsgs)
            if ofmsg.match.get("in_port") == in_port
        ]

    def _learn(self, in_port):
        ucast_pkt = self.pkt_match(in_port, 1)
        ucast_pkt["in_port"] = in_port
        ucast_pkt["vlan_vid"] = self.V100

        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(ucast_pkt, port=CONTROLLER_PORT))
        self.rcv_packet(in_port, self.V100, ucast_pkt)

    def _unicast_between(self, in_port, out_port, not_out=1):
        ucast_match = self.pkt_match(in_port, out_port)
        ucast_match["in_port"] = in_port
        ucast_match["vlan_vid"] = self.V100

        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(ucast_match, port=out_port))
        self.assertFalse(table.is_output(ucast_match, port=not_out))

    def setUp(self):
        initial_ofmsgs = self.setup_valves(self.CONFIG)[self.DP_ID]
        self.assertFalse(self._inport_flows(3, initial_ofmsgs))

    def test_port_add_no_ofmsgs(self):
        """New config does not generate new flows."""
        update_ofmsgs = self.update_config(self.MORE_CONFIG, reload_type="warm")[
            self.DP_ID
        ]
        self.assertFalse(self._inport_flows(3, update_ofmsgs))

    def test_port_add_link_state(self):
        """New port can be added in link-down state."""
        self.update_config(self.MORE_CONFIG, reload_type="warm")

        self.add_port(3, link_up=False)
        self.port_expected_status(3, 0)

        self.set_port_link_up(3)
        self.port_expected_status(3, 1)

    def test_port_add_traffic(self):
        """New port can be added, and pass traffic."""
        self.update_config(self.MORE_CONFIG, reload_type="warm")

        self.add_port(3)

        self._learn(2)
        self._learn(3)

        self._unicast_between(2, 3)
        self._unicast_between(3, 2)


class ValveWarmStartVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test change of port VLAN only is a warm start."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 9
                tagged_vlans: [0x100]
            p2:
                number: 11
                tagged_vlans: [0x100]
            p3:
                number: 13
                tagged_vlans: [0x100]
            p4:
                number: 14
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    WARM_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 9
                tagged_vlans: [0x100]
            p2:
                number: 11
                tagged_vlans: [0x100]
            p3:
                number: 13
                tagged_vlans: [0x100]
            p4:
                number: 14
                native_vlan: 0x300
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_warm_start(self):
        """Test VLAN change is warm startable and metrics maintained."""
        self.update_and_revert_config(self.CONFIG, self.WARM_CONFIG, "warm")
        self.rcv_packet(
            9,
            0x100,
            {
                "eth_src": self.P1_V100_MAC,
                "eth_dst": self.UNKNOWN_MAC,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.2",
            },
        )
        vlan_labels = {"vlan": str(int(0x100))}
        port_labels = {"port": "p1", "port_description": "p1"}
        port_labels.update(vlan_labels)

        def verify_func():
            self.assertEqual(1, self.get_prom("vlan_hosts_learned", labels=vlan_labels))
            self.assertEqual(
                1, self.get_prom("port_vlan_hosts_learned", labels=port_labels)
            )

        verify_func()
        self.update_config(self.WARM_CONFIG, reload_type="warm")
        verify_func()


class ValveChangeVIPWarmStartTestCase(ValveTestBases.ValveTestNetwork):
    """Test changing VIP address on a VLAN is a warm start."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    NEW_VIP_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.253/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_change_vip(self):
        """Test changing a VIP address is warm startable."""
        self.update_and_revert_config(self.CONFIG, self.NEW_VIP_CONFIG, "warm")


class ValveChangeVIPSingleVLANAllPortsWarmStartTestCase(
    ValveTestBases.ValveTestNetwork
):
    """VIP change on a DP whose only VLAN owns every port must warm restart."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: office
            p2:
                number: 2
                native_vlan: office
vlans:
    office:
        vid: 100
        faucet_vips: ['10.0.0.1/24']
        faucet_mac: '00:00:00:00:00:11'
"""
        % DP1_CONFIG
    )

    NEW_VIP_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: office
            p2:
                number: 2
                native_vlan: office
vlans:
    office:
        vid: 100
        faucet_vips: ['10.0.0.2/24']
        faucet_mac: '00:00:00:00:00:11'
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_change_vip(self):
        """Test changing a VIP address with single VLAN owning all ports is warm."""
        self.update_and_revert_config(self.CONFIG, self.NEW_VIP_CONFIG, "warm")


class ValveChangeRouterWarmStartTestCase(ValveTestBases.ValveTestNetwork):
    """Test changing router VLAN membership is a warm start."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
            p3:
                number: 3
                native_vlan: 0x300
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
    v300:
        vid: 0x300
        faucet_vips: ['10.0.2.254/24']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    NEW_ROUTER_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
            p3:
                number: 3
                native_vlan: 0x300
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
    v300:
        vid: 0x300
        faucet_vips: ['10.0.2.254/24']
routers:
    router1:
        vlans: [v100, v200, v300]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_change_router_membership(self):
        """Test changing router VLAN membership is warm startable."""
        self.update_and_revert_config(self.CONFIG, self.NEW_ROUTER_CONFIG, "warm")


class ValveAddRouterWithNewVlanWarmStartTestCase(ValveTestBases.ValveTestNetwork):
    """A router membership change that simultaneously adds a brand-new
    VLAN must put the new VID in added_vlans only; the router-affected
    expansion must not also place it in changed_vlans (otherwise the
    valve.py reload path runs add_vlans for it twice)."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                tagged_vlans: [0x100, 0x200]
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    NEW_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200, 0x300]
            p2:
                number: 2
                tagged_vlans: [0x100, 0x200, 0x300]
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
    v300:
        vid: 0x300
        faucet_vips: ['10.0.2.254/24']
routers:
    router1:
        vlans: [v100, v200, v300]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_disjoint_added_and_changed(self):
        """get_config_changes must return v300 in added_vlans only,
        not in changed_vlans."""
        new_dp = _parse_dp(self.tmpdir, "new.yaml", self.NEW_CONFIG)
        old_dp = self.valves_manager.valves[self.DP_ID].dp
        changes = old_dp.get_config_changes(
            self.valves_manager.valves[self.DP_ID].logger, new_dp
        )
        self.assertIn(0x300, changes.added_vlans, "new VID should land in added_vlans")
        self.assertNotIn(
            0x300,
            changes.changed_vlans,
            "new VID must not also be in changed_vlans (would cause "
            "redundant add_vlans pass)",
        )


class ValveRouterAclCombinedChangeDisjointnessTestCase(ValveTestBases.ValveTestNetwork):
    """When a router-membership change pulls a VID into changed_vlans via
    affected-VLAN expansion, and that same VID's only direct change is an
    ACL ref, the VID must end up in changed_vlans only -- not also in
    changed_acl_vlans -- otherwise the heavy reinstall path and the
    granular ACL path both fire and double-emit ACL flows."""

    CONFIG = (
        """
acls:
    block-ping:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
        acls_in: [block-ping]
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                tagged_vlans: [0x100, 0x200]
routers:
    router1:
        vlans: [v100]
"""
        % DP1_CONFIG
    )

    NEW_CONFIG = (
        """
acls:
    block-ping:
        - rule:
            dl_type: 0x800
            ip_proto: 1
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            ip_proto: 6
            actions:
                allow: 0
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
        acls_in: [block-ping]
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                tagged_vlans: [0x100, 0x200]
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_router_expansion_does_not_violate_disjointness(self):
        new_dp = _parse_dp(self.tmpdir, "router_acl.yaml", self.NEW_CONFIG)
        old_dp = self.valves_manager.valves[self.DP_ID].dp
        changes = old_dp.get_config_changes(
            self.valves_manager.valves[self.DP_ID].logger, new_dp
        )
        # Router membership expanded changed_vlans to include v100; v100 was
        # also flagged as ACL-only. Disjointness must put it in the heavy
        # path only.
        self.assertIn(0x100, changes.changed_vlans, "router-affected VID missing")
        self.assertNotIn(
            0x100,
            changes.changed_acl_vlans,
            "VID is in BOTH changed_vlans (heavy reinstall) and "
            "changed_acl_vlans (granular reload); both paths would fire "
            "and double-emit ACL flows",
        )


def _parse_dp(tmpdir, filename, config):
    """Parse `config` to a DP via dp_parser, using a temp file under tmpdir."""
    path = os.path.join(tmpdir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(config)
    _, _, dps, _ = config_parser.dp_parser(path, "test")
    return dps[0]


class ValveRemoveVIPWarmStartTestCase(ValveTestBases.ValveTestNetwork):
    """Test removing VIPs from a VLAN is a warm start (when routing tables remain)."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    LESS_VIP_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
routers:
    router1:
        vlans: [v100]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_remove_vip(self):
        """Test removing VIPs from a VLAN is warm startable."""
        self.update_and_revert_config(self.CONFIG, self.LESS_VIP_CONFIG, "warm")


class ValveDeleteRoutedVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test deleting a VLAN referenced by a router doesn't crash."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
            p3:
                number: 3
                native_vlan: 0x300
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
    v300:
        vid: 0x300
        faucet_vips: ['10.0.2.254/24']
routers:
    router1:
        vlans: [v100, v200, v300]
"""
        % DP1_CONFIG
    )

    DELETE_VLAN_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_delete_routed_vlan(self):
        """Test deleting a VLAN referenced by a router doesn't crash."""
        self.update_and_revert_config(self.CONFIG, self.DELETE_VLAN_CONFIG, "cold")


class ValveChangeIPv6VIPWarmStartTestCase(ValveTestBases.ValveTestNetwork):
    """Test changing an IPv6 VIP is a warm start."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['fc00::1:254/112', 'fe80::1:254/64']
    v200:
        vid: 0x200
        faucet_vips: ['fc00::2:254/112', 'fe80::2:254/64']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    NEW_VIP_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['fc00::1:253/112', 'fe80::1:254/64']
    v200:
        vid: 0x200
        faucet_vips: ['fc00::2:254/112', 'fe80::2:254/64']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_change_ipv6_vip(self):
        """Test changing an IPv6 VIP address is warm startable."""
        self.update_and_revert_config(self.CONFIG, self.NEW_VIP_CONFIG, "warm")


class ValveAddRouterWithExistingVipsWarmStartTestCase(ValveTestBases.ValveTestNetwork):
    """Adding a router when VLANs already have VIPs warm-restarts.
    The "no existing routing tables" cold-start gate must NOT fire when
    any OLD VLAN already has faucet_vips configured."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
"""
        % DP1_CONFIG
    )

    ADD_ROUTER_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_add_router_with_existing_vips(self):
        self.update_and_revert_config(self.CONFIG, self.ADD_ROUTER_CONFIG, "warm")


class ValveAddRouterNoVipsColdStartTestCase(ValveTestBases.ValveTestNetwork):
    """Adding a router when no VLAN has VIPs must cold-restart.
    The "no existing routing tables" gate exists because routing
    infrastructure (FIB tables, VIP select_packets flows) has to be
    built from scratch on first introduction."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
"""
        % DP1_CONFIG
    )

    ADD_ROUTER_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
        faucet_vips: ['10.0.1.254/24']
routers:
    router1:
        vlans: [v100, v200]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_add_router_no_old_vips(self):
        self.update_and_revert_config(self.CONFIG, self.ADD_ROUTER_CONFIG, "cold")


class ValveBGPColdStartTestCase(ValveTestBases.ValveTestNetwork):
    """Test that BGP config changes still trigger cold start."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
routers:
    router1:
        vlans: [v100, v200]
        bgp:
            as: 1
            connect_mode: passive
            neighbor_addresses: ['127.0.0.1']
            neighbor_as: 2
            port: 9179
            routerid: '1.1.1.1'
            server_addresses: ['127.0.0.1']
            vlan: v100
"""
        % DP1_CONFIG
    )

    BGP_CHANGE_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
    v200:
        vid: 0x200
routers:
    router1:
        vlans: [v100, v200]
        bgp:
            as: 1
            connect_mode: passive
            neighbor_addresses: ['127.0.0.1']
            neighbor_as: 3
            port: 9179
            routerid: '1.1.1.1'
            server_addresses: ['127.0.0.1']
            vlan: v100
"""
        % DP1_CONFIG
    )

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_bgp_change_cold_start(self):
        """Test that changing BGP config still requires cold start."""
        self.update_and_revert_config(self.CONFIG, self.BGP_CHANGE_CONFIG, "cold")


class ValveDeleteVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test deleting VLAN."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    LESS_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x200]
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_delete_vlan(self):
        """Test VLAN can be deleted."""
        self.update_and_revert_config(self.CONFIG, self.LESS_CONFIG, "cold")


class ValveChangeDPTestCase(ValveTestBases.ValveTestNetwork):
    """Test changing DP."""

    CONFIG = (
        """
dps:
    s1:
%s
        priority_offset: 4321
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    NEW_CONFIG = (
        """
dps:
    s1:
%s
        priority_offset: 1234
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config with priority offset"""
        self.setup_valves(self.CONFIG)

    def test_change_dp(self):
        """Test DP changed."""
        self.update_and_revert_config(self.CONFIG, self.NEW_CONFIG, "cold")


class ValveAddVLANTestCase(ValveTestBases.ValveTestNetwork):
    """Test adding VLAN."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                tagged_vlans: [0x100]
"""
        % DP1_CONFIG
    )

    MORE_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                tagged_vlans: [0x100, 0x300]
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_add_vlan(self):
        """Test VLAN can added."""
        self.update_and_revert_config(self.CONFIG, self.MORE_CONFIG, "cold")


class ValveChangeACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test changes to ACL on a port."""

    CONFIG = (
        """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_same_a
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    SAME_CONTENT_CONFIG = (
        """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_same_b
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    DIFF_CONTENT_CONFIG = (
        """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_diff_c
            p2:
                number: 2
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic ACL config"""
        self.setup_valves(self.CONFIG)

    def test_change_port_acl(self):
        """Test port ACL can be changed."""
        self.update_and_revert_config(self.CONFIG, self.SAME_CONTENT_CONFIG, "warm")
        self.update_config(self.SAME_CONTENT_CONFIG, reload_type="warm")
        self.rcv_packet(
            1,
            0x100,
            {
                "eth_src": self.P1_V100_MAC,
                "eth_dst": self.UNKNOWN_MAC,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.2",
            },
        )
        vlan_labels = {"vlan": str(int(0x100))}
        port_labels = {"port": "p1", "port_description": "p1"}
        port_labels.update(vlan_labels)

        def verify_func():
            self.assertEqual(1, self.get_prom("vlan_hosts_learned", labels=vlan_labels))
            self.assertEqual(
                1, self.get_prom("port_vlan_hosts_learned", labels=port_labels)
            )

        verify_func()
        # ACL changed but we kept the learn cache.
        self.update_config(self.DIFF_CONTENT_CONFIG, reload_type="warm")
        verify_func()


class ValveChangeMirrorTestCase(ValveTestBases.ValveTestNetwork):
    """Test changes mirroring port."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                output_only: True
            p3:
                number: 3
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    MIRROR_CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                mirror: p1
            p3:
                number: 3
                native_vlan: 0x200
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_change_port_acl(self):
        """Test port ACL can be changed."""
        self.update_and_revert_config(
            self.CONFIG, self.MIRROR_CONFIG, reload_type="warm"
        )

        vlan_labels = {"vlan": str(int(0x100))}
        port_labels = {"port": "p1", "port_description": "p1"}
        port_labels.update(vlan_labels)

        def verify_prom():
            self.assertEqual(1, self.get_prom("vlan_hosts_learned", labels=vlan_labels))
            self.assertEqual(
                1, self.get_prom("port_vlan_hosts_learned", labels=port_labels)
            )

        self.rcv_packet(
            1,
            0x100,
            {
                "eth_src": self.P1_V100_MAC,
                "eth_dst": self.UNKNOWN_MAC,
                "ipv4_src": "10.0.0.1",
                "ipv4_dst": "10.0.0.2",
            },
        )

        verify_prom()
        # Now mirroring port 1 but we kept the cache.
        self.update_config(self.MIRROR_CONFIG, reload_type="warm")
        verify_prom()
        # Now unmirror again.
        self.update_config(self.CONFIG, reload_type="warm")
        verify_prom()


class ValveACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test ACL drop/allow and reloading."""

    def setUp(self):
        self.setup_valves(CONFIG)

    def test_vlan_acl_deny(self):
        """Test VLAN ACL denies a packet."""
        acl_config = (
            """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                native_vlan: v300
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
        acl_in: drop_non_ospf_ipv4
    v300:
        vid: 0x300
acls:
    drop_non_ospf_ipv4:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                allow: 1
        - rule:
            dl_type: 0x800
            actions:
                allow: 0
"""
            % DP1_CONFIG
        )

        drop_match = {
            "in_port": 2,
            "vlan_vid": 0,
            "eth_type": 0x800,
            "ipv4_dst": "192.0.2.1",
        }
        accept_match = {
            "in_port": 2,
            "vlan_vid": 0,
            "eth_type": 0x800,
            "ipv4_dst": "224.0.0.5",
        }
        table = self.network.tables[self.DP_ID]

        # base case
        for match in (drop_match, accept_match):
            self.assertTrue(
                table.is_output(match, port=3, vid=self.V200),
                msg="Packet not output before adding ACL",
            )

        def verify_func():
            self.flap_port(2)
            self.assertFalse(
                table.is_output(drop_match), msg="Packet not blocked by ACL"
            )
            self.assertTrue(
                table.is_output(accept_match, port=3, vid=self.V200),
                msg="Packet not allowed by ACL",
            )

        self.update_and_revert_config(
            CONFIG, acl_config, reload_type="cold", verify_func=verify_func
        )


class ValveEgressACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test ACL drop/allow and reloading."""

    def setUp(self):
        self.setup_valves(CONFIG)

    def test_vlan_acl_deny(self):
        """Test VLAN ACL denies a packet."""
        allow_host_v6 = "fc00:200::1:1"
        deny_host_v6 = "fc00:200::1:2"
        faucet_v100_vip = "fc00:100::1"
        faucet_v200_vip = "fc00:200::1"
        acl_config = """
dps:
    s1:
{dp1_config}
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
vlans:
    v100:
        vid: 0x100
        faucet_mac: '{mac}'
        faucet_vips: ['{v100_vip}/64']
    v200:
        vid: 0x200
        faucet_mac: '{mac}'
        faucet_vips: ['{v200_vip}/64']
        acl_out: drop_non_allow_host_v6
        minimum_ip_size_check: false
routers:
    r_v100_v200:
        vlans: [v100, v200]
acls:
    drop_non_allow_host_v6:
        - rule:
            ipv6_dst: '{allow_host}'
            eth_type: 0x86DD
            actions:
                allow: 1
        - rule:
            eth_type: 0x86DD
            actions:
                allow: 0
""".format(
            dp1_config=DP1_CONFIG,
            mac=FAUCET_MAC,
            v100_vip=faucet_v100_vip,
            v200_vip=faucet_v200_vip,
            allow_host=allow_host_v6,
        )

        l2_drop_match = {
            "in_port": 2,
            "eth_dst": self.P3_V200_MAC,
            "vlan_vid": 0,
            "eth_type": 0x86DD,
            "ipv6_dst": deny_host_v6,
        }
        l2_accept_match = {
            "in_port": 3,
            "eth_dst": self.P2_V200_MAC,
            "vlan_vid": 0x200 | ofp.OFPVID_PRESENT,
            "eth_type": 0x86DD,
            "ipv6_dst": allow_host_v6,
        }
        v100_accept_match = {"in_port": 1, "vlan_vid": 0}
        table = self.network.tables[self.DP_ID]

        # base case
        for match in (l2_drop_match, l2_accept_match):
            self.assertTrue(
                table.is_output(match, port=4),
                msg="Packet not output before adding ACL",
            )

        def verify_func():
            self.assertTrue(
                table.is_output(v100_accept_match, port=3),
                msg="Packet not output when on vlan with no ACL",
            )
            self.assertFalse(
                table.is_output(l2_drop_match, port=3), msg="Packet not blocked by ACL"
            )
            self.assertTrue(
                table.is_output(l2_accept_match, port=2),
                msg="Packet not allowed by ACL",
            )

            # unicast
            self.rcv_packet(
                2,
                0x200,
                {
                    "eth_src": self.P2_V200_MAC,
                    "eth_dst": self.P3_V200_MAC,
                    "vid": 0x200,
                    "ipv6_src": allow_host_v6,
                    "ipv6_dst": deny_host_v6,
                    "neighbor_advert_ip": allow_host_v6,
                },
            )
            self.rcv_packet(
                3,
                0x200,
                {
                    "eth_src": self.P3_V200_MAC,
                    "eth_dst": self.P2_V200_MAC,
                    "vid": 0x200,
                    "ipv6_src": deny_host_v6,
                    "ipv6_dst": allow_host_v6,
                    "neighbor_advert_ip": deny_host_v6,
                },
            )

            self.assertTrue(
                table.is_output(l2_accept_match, port=2),
                msg="Packet not allowed by ACL",
            )
            self.assertFalse(
                table.is_output(l2_drop_match, port=3), msg="Packet not blocked by ACL"
            )

            # l3
            l3_drop_match = {
                "in_port": 1,
                "eth_dst": FAUCET_MAC,
                "vlan_vid": 0,
                "eth_type": 0x86DD,
                "ipv6_dst": deny_host_v6,
            }
            l3_accept_match = {
                "in_port": 1,
                "eth_dst": FAUCET_MAC,
                "vlan_vid": 0,
                "eth_type": 0x86DD,
                "ipv6_dst": allow_host_v6,
            }

            self.assertTrue(
                table.is_output(l3_accept_match, port=2),
                msg="Routed packet not allowed by ACL",
            )
            self.assertFalse(
                table.is_output(l3_drop_match, port=3),
                msg="Routed packet not blocked by ACL",
            )

        # multicast
        self.update_and_revert_config(
            CONFIG, acl_config, "cold", verify_func=verify_func
        )


class ValveReloadConfigProfile(ValveTestBases.ValveTestNetwork):
    """Test reload processing time."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""
        % BASE_DP1_CONFIG
    )
    NUM_PORTS = 100

    baseline_total_tt = None

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(CONFIG)

    def test_profile_reload(self):
        """Test reload processing time."""
        orig_config = copy.copy(self.CONFIG)

        def load_orig_config():
            pstats_out, _ = self.profile(partial(self.update_config, orig_config))
            self.baseline_total_tt = (
                pstats_out.total_tt
            )  # pytype: disable=attribute-error

        for i in range(2, 100):
            self.CONFIG += """
            p%u:
                number: %u
                native_vlan: 0x100
""" % (
                i,
                i,
            )

        for i in range(5):
            load_orig_config()
            pstats_out, pstats_text = self.profile(
                partial(self.update_config, self.CONFIG, reload_type="cold")
            )
            cache_info = valve_of.output_non_output_actions.cache_info()
            self.assertGreater(cache_info.hits, cache_info.misses, msg=cache_info)
            total_tt_prop = (
                pstats_out.total_tt / self.baseline_total_tt
            )  # pytype: disable=attribute-error
            # must not be 20x slower, to ingest config for 100 interfaces than 1.
            # TODO: This test might have to be run separately,
            # since it is marginal on GitHub actions due to parallel test runs.
            if total_tt_prop < 20:
                for valve in self.valves_manager.valves.values():
                    for table in valve.dp.tables.values():
                        cache_info = (
                            table._trim_inst.cache_info()
                        )  # pylint: disable=protected-access
                        self.assertGreater(
                            cache_info.hits, cache_info.misses, msg=cache_info
                        )
                return
            time.sleep(i)

        self.fail("%f: %s" % (total_tt_prop, pstats_text))


class ValveTestVLANRef(ValveTestBases.ValveTestNetwork):
    """Test reference to same VLAN by name or VID."""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 333
            p2:
                number: 2
                native_vlan: threes
vlans:
    threes:
        vid: 333
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def test_vlan_refs(self):
        """Test same VLAN is referred to."""
        vlans = self.valves_manager.valves[self.DP_ID].dp.vlans
        self.assertEqual(1, len(vlans))
        self.assertEqual("threes", vlans[333].name, vlans[333])
        self.assertEqual(2, len(vlans[333].untagged))


class ValveTestConfigHash(ValveTestBases.ValveTestNetwork):
    """Verify faucet_config_hash_info update after config change"""

    CONFIG = (
        """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""
        % DP1_CONFIG
    )

    def setUp(self):
        """Setup basic port and vlan config"""
        self.setup_valves(self.CONFIG)

    def _get_info(self, metric, name):
        """Return (single) info dict for metric"""
        # There doesn't seem to be a nice API for this,
        # so we use the prometheus client internal API
        metrics = list(metric.collect())
        self.assertEqual(len(metrics), 1)
        samples = metrics[0].samples
        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(sample.name, name)
        return sample.labels

    def _check_hashes(self):
        """Verify and return faucet_config_hash_info labels"""
        labels = self._get_info(
            metric=self.metrics.faucet_config_hash, name="faucet_config_hash_info"
        )
        files = labels["config_files"].split(",")
        hashes = labels["hashes"].split(",")
        self.assertTrue(len(files) == len(hashes) == 1)
        self.assertEqual(files[0], self.config_file, "wrong config file")
        hash_value = config_parser_util.config_file_hash(self.config_file)
        self.assertEqual(hashes[0], hash_value, "hash validation failed")
        return labels

    def _change_config(self):
        """Change self.CONFIG"""
        if "0x100" in self.CONFIG:
            self.CONFIG = self.CONFIG.replace("0x100", "0x200")
        else:
            self.CONFIG = self.CONFIG.replace("0x200", "0x100")
        self.update_config(self.CONFIG, reload_expected=True)
        return self.CONFIG

    def test_config_hash_func(self):
        """Verify that faucet_config_hash_func is set correctly"""
        labels = self._get_info(
            metric=self.metrics.faucet_config_hash_func, name="faucet_config_hash_func"
        )
        hash_funcs = list(labels.values())
        self.assertEqual(len(hash_funcs), 1, "found multiple hash functions")
        hash_func = hash_funcs[0]
        # Make sure that it matches and is supported in hashlib
        self.assertEqual(hash_func, config_parser_util.CONFIG_HASH_FUNC)
        self.assertTrue(hash_func in hashlib.algorithms_guaranteed)

    def test_config_hash_update(self):
        """Verify faucet_config_hash_info is properly updated after config"""
        # Verify that hashes change after config is changed
        old_config = self.CONFIG
        old_hashes = self._check_hashes()
        starting_hashes = old_hashes
        self._change_config()
        new_config = self.CONFIG
        self.assertNotEqual(old_config, new_config, "config not changed")
        new_hashes = self._check_hashes()
        self.assertNotEqual(
            old_hashes, new_hashes, "hashes not changed after config change"
        )
        # Verify that hashes don't change after config isn't changed
        old_hashes = new_hashes
        self.update_config(self.CONFIG, reload_expected=False)
        new_hashes = self._check_hashes()
        self.assertEqual(old_hashes, new_hashes, "hashes changed when config didn't")
        # Verify that hash is restored when config is restored
        self._change_config()
        new_hashes = self._check_hashes()
        self.assertEqual(
            new_hashes, starting_hashes, "hashes should be restored to starting values"
        )


class ValveTestConfigRevert(ValveTestBases.ValveTestNetwork):
    """Test configuration revert"""

    CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""

    CONFIG_AUTO_REVERT = True

    def setUp(self):
        """Setup basic port and vlan config with hardware type set"""
        self.setup_valves(self.CONFIG)

    def test_config_revert(self):
        """Verify config is automatically reverted if bad."""
        self.assertEqual(self.get_prom("faucet_config_load_error", bare=True), 0)
        self.update_config("***broken***", reload_expected=True, error_expected=1)
        self.assertEqual(self.get_prom("faucet_config_load_error", bare=True), 1)
        with open(self.config_file, "r", encoding="utf-8") as config_file:
            config_content = config_file.read()
        self.assertEqual(self.CONFIG, config_content)
        self.update_config(self.CONFIG + "\n", reload_expected=False, error_expected=0)
        more_config = (
            self.CONFIG
            + """
            p2:
                number: 2
                native_vlan: 0x100
        """
        )
        self.update_config(
            more_config, reload_expected=True, reload_type="warm", error_expected=0
        )


class ValveTestConfigRevertBootstrap(ValveTestBases.ValveTestNetwork):
    """Test configuration auto reverted if bad"""

    BAD_CONFIG = """
    *** busted ***
"""
    GOOD_CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""

    CONFIG_AUTO_REVERT = True

    def setUp(self):
        """Setup invalid config"""
        self.setup_valves(self.BAD_CONFIG, error_expected=1)

    def test_config_revert(self):
        """Verify config is automatically reverted if bad."""
        self.assertEqual(self.get_prom("faucet_config_load_error", bare=True), 1)
        self.update_config(
            self.GOOD_CONFIG + "\n", reload_expected=False, error_expected=0
        )
        self.assertEqual(self.get_prom("faucet_config_load_error", bare=True), 0)


class ValveTestConfigApplied(ValveTestBases.ValveTestNetwork):
    """Test cases for faucet_config_applied."""

    CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            p1:
                description: "one thing"
                number: 1
                native_vlan: 0x100
"""
    NEW_DESCR_CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            p1:
                description: "another thing"
                number: 1
                native_vlan: 0x100
"""

    def setUp(self):
        """Setup basic port and vlan config with hardware type set"""
        self.setup_valves(self.CONFIG)

    def test_config_applied_update(self):
        """Verify that config_applied increments after DP connect"""
        # 100% for a single datapath
        self.assertEqual(self.get_prom("faucet_config_applied", bare=True), 1.0)
        # Add a second datapath, which currently isn't programmed
        self.CONFIG += """
    s2:
        dp_id: 0x2
        hardware: 'GenericTFM'
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""
        self.update_config(self.CONFIG, reload_expected=False)
        # Should be 50%
        self.assertEqual(self.get_prom("faucet_config_applied", bare=True), 0.5)
        # We don't have a way to simulate the second datapath connecting,
        # we update the statistic manually
        self.valves_manager.update_config_applied({0x2: True})
        # Should be 100% now
        self.assertEqual(self.get_prom("faucet_config_applied", bare=True), 1.0)

    def test_description_only(self):
        """Test updating config description"""
        self.update_config(self.NEW_DESCR_CONFIG, reload_expected=False)


class ValveReloadConfigTestCase(
    ValveTestBases.ValveTestBig
):  # pylint: disable=too-few-public-methods
    """Repeats the tests after a config reload."""

    def setUp(self):
        super().setUp()
        self.flap_port(1)
        self.update_config(CONFIG, reload_type="warm", reload_expected=False)


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
