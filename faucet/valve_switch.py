"""Manage flooding/learning on datapaths."""

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

from faucet.valve_switch_standalone import (
    ValveSwitchManager, ValveSwitchFlowRemovedManager)
from faucet.valve_switch_stack import (
    ValveSwitchStackManagerNoReflection, ValveSwitchStackManagerReflection)


def valve_switch_factory(logger, dp, pipeline):  # pylint: disable=invalid-name
    """Return switch flood/learning manager based on datapath configuration.

        Args:
            logger: logger instance.
            dp: DP instance.
            pipeline: ValvePipeline instance.
        Returns:
            switch manager instance.
    """
    restricted_bcast_arpnd = bool(dp.restricted_bcast_arpnd_ports())
    eth_dst_hairpin_table = dp.tables.get('eth_dst_hairpin', None)
    vlan_acl_table = dp.tables.get('vlan_acl', None)

    if dp.stack_graph:
        switch_class = ValveSwitchStackManagerNoReflection
        if dp.stack_root_flood_reflection:
            switch_class = ValveSwitchStackManagerReflection
            logger.info('Using stacking root flood reflection')
        else:
            logger.info('Not using stacking root flood reflection')
        return switch_class(
            logger, dp.ports, dp.vlans,
            dp.tables['vlan'], vlan_acl_table, dp.tables['eth_src'], dp.tables['eth_dst'],
            eth_dst_hairpin_table, dp.tables['flood'], dp.classification_table,
            pipeline, dp.group_table, dp.groups,
            dp.combinatorial_port_flood, dp.canonical_port_order,
            restricted_bcast_arpnd, dp.has_externals,
            dp.learn_ban_timeout, dp.timeout, dp.learn_jitter,
            dp.cache_update_guard_time, dp.idle_dst,
            dp.stack_ports,
            dp.shortest_path_to_root, dp.shortest_path_port,
            dp.is_stack_root, dp.is_stack_root_candidate,
            dp.is_stack_edge, dp.stack_graph)

    if dp.use_idle_timeout:
        switch_class = ValveSwitchFlowRemovedManager
    else:
        switch_class = ValveSwitchManager
    return switch_class(
        logger, dp.ports, dp.vlans,
        dp.tables['vlan'], vlan_acl_table, dp.tables['eth_src'], dp.tables['eth_dst'],
        eth_dst_hairpin_table, dp.tables['flood'], dp.classification_table,
        pipeline, dp.group_table, dp.groups,
        dp.combinatorial_port_flood, dp.canonical_port_order,
        restricted_bcast_arpnd, dp.has_externals,
        dp.learn_ban_timeout, dp.timeout, dp.learn_jitter, dp.cache_update_guard_time, dp.idle_dst)
