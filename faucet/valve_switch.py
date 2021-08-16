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


def valve_switch_factory(logger, dp, pipeline, stack_manager):
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

    switch_args = {
        'logger': logger,
        'ports': dp.ports,
        'vlans': dp.vlans,
        'vlan_table': dp.tables['vlan'],
        'vlan_acl_table': vlan_acl_table,
        'eth_src_table': dp.tables['eth_src'],
        'eth_dst_table': dp.tables['eth_dst'],
        'eth_dst_hairpin_table': eth_dst_hairpin_table,
        'flood_table': dp.tables['flood'],
        'classification_table': dp.classification_table,
        'pipeline': pipeline,
        'use_group_table': dp.group_table,
        'groups': dp.groups,
        'combinatorial_port_flood': dp.combinatorial_port_flood,
        'canonical_port_order': dp.canonical_port_order,
        'restricted_bcast_arpnd': restricted_bcast_arpnd,
        'has_externals': dp.has_externals,
        'learn_ban_timeout': dp.learn_ban_timeout,
        'learn_timeout': dp.timeout,
        'learn_jitter': dp.learn_jitter,
        'cache_update_guard_time': dp.cache_update_guard_time,
        'idle_dst': dp.idle_dst,
        'dp_high_priority': dp.high_priority,
        'dp_highest_priority': dp.highest_priority,
        'faucet_dp_mac': dp.faucet_dp_mac,
        'drop_spoofed_faucet_mac': dp.drop_spoofed_faucet_mac,
    }

    if dp.stack:
        switch_class = ValveSwitchStackManagerNoReflection
        if dp.stack.root_flood_reflection:
            switch_class = ValveSwitchStackManagerReflection
            logger.info('Using stacking root flood reflection')
        else:
            logger.info('Not using stacking root flood reflection')
        switch_args.update({
            'stack_manager': stack_manager,
        })
        return switch_class(**switch_args)

    switch_class = ValveSwitchManager
    if dp.use_idle_timeout:
        switch_class = ValveSwitchFlowRemovedManager
    return switch_class(**switch_args)  # pytype: disable=wrong-keyword-args
