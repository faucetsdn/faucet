# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
# Copyright (C) 2015 Research and Education Advanced Network New Zealand Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASISo
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


class ValveRouteManager(object):

    def __init__(self, fib_table):
        self.fib_table = fib_table


class ValveIPv4RouteManager(ValveRouteManager):

    def eth_type(self):
        return ether.ETH_TYPE_IP

    def vlan_routes(self, vlan):
        return vlan.ipv4_routes

    def vlan_neighbor_cache(self, vlan):
        return vlan.arp_cache



class ValveIPv6RouteManager(ValveRouteManager):

    def eth_type(self):
        return ether.ETH_TYPE_IPV6

    def vlan_routes(self, vlan):
        return vlan.ipv6_routes

    def vlan_neighbor_cache(self, vlan):
        return vlan.nd_cache
