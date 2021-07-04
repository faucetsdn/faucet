"""Manage higher level stack functions"""


from collections import defaultdict

from faucet.valve_manager_base import ValveManagerBase


class ValveStackManager(ValveManagerBase):
    """Implement stack manager, this handles the more higher-order stack functions.
This includes port nominations and flood directionality."""

    def __init__(self, logger, dp, stack, tunnel_acls, acl_manager, output_table, **_kwargs):
        """
        Initialize variables and set up peer distances

        Args:
            stack (Stack): Stack object of the DP on the Valve being managed
        """
        # Logger for logging
        self.logger = logger
        # DP instance for stack healthyness
        self.dp = dp  # pylint: disable=invalid-name
        # Stack instance
        self.stack = stack

        # Used the manage the tunnel ACLs which requires stack knowledge
        self.tunnel_acls = tunnel_acls
        self.acl_manager = acl_manager
        self.output_table = output_table

        # Ports that are the shortest distance to the root
        self.towards_root_ports = None
        # Ports on an adjacent DP that is the chosen shortest path to the root
        self.chosen_towards_ports = None
        # Single port on the adjacent shortest path DP
        self.chosen_towards_port = None

        # All ports that are not the shortest distance to the root
        self.away_ports = None
        # Ports whose peer DPs have a shorter path to root
        self.inactive_away_ports = None
        # Redundant ports for each adjacent DP
        self.pruned_away_ports = None

        self.reset_peer_distances()

    @staticmethod
    def stacked_valves(valves):
        """Return set of valves that have stacking enabled"""
        return {valve for valve in valves if valve.dp.stack and valve.dp.stack.root_name}

    def reset_peer_distances(self):
        """Recalculates the towards and away ports for this node"""
        self.towards_root_ports = set()
        self.chosen_towards_ports = set()
        self.chosen_towards_port = None

        self.away_ports = set()
        self.inactive_away_ports = set()
        self.pruned_away_ports = set()

        all_peer_ports = set(self.stack.canonical_up_ports())
        if self.stack.is_root():
            self.away_ports = all_peer_ports
        else:
            port_peer_distances = {
                port: len(port.stack['dp'].stack.shortest_path_to_root())
                for port in all_peer_ports}
            shortest_peer_distance = None
            for port, port_peer_distance in port_peer_distances.items():
                if shortest_peer_distance is None:
                    shortest_peer_distance = port_peer_distance
                    continue
                shortest_peer_distance = min(shortest_peer_distance, port_peer_distance)
            self.towards_root_ports = {
                port for port, port_peer_distance in port_peer_distances.items()
                if port_peer_distance == shortest_peer_distance}

            self.away_ports = all_peer_ports - self.towards_root_ports

            if self.towards_root_ports:
                # Generate a shortest path to calculate the chosen connection to root
                shortest_path = self.stack.shortest_path_to_root()
                # Choose the port that is connected to peer DP
                if shortest_path and len(shortest_path) > 1:
                    first_peer_dp = shortest_path[1]
                else:
                    first_peer_port = self.stack.canonical_port_order(
                        self.towards_root_ports)[0]
                    first_peer_dp = first_peer_port.stack['dp'].name
                # The chosen towards ports are the ports through the chosen peer DP
                self.chosen_towards_ports = {
                    port for port in self.towards_root_ports
                    if port.stack['dp'].name == first_peer_dp}  # pytype: disable=attribute-error

            if self.chosen_towards_ports:
                self.chosen_towards_port = self.stack.canonical_up_ports(
                    self.chosen_towards_ports)[0]

            # Away ports are all the remaining (non-towards) ports
            self.away_ports = all_peer_ports - self.towards_root_ports

        if self.away_ports:
            # Get inactive away ports, ports whose peers have a better path to root
            self.inactive_away_ports = {
                port for port in self.away_ports
                if not self.stack.is_in_path(port.stack['dp'].name, self.stack.root_name)}

            # Get pruned away ports, redundant ports for each adjacent DP
            ports_by_dp = defaultdict(list)
            for port in self.away_ports:
                ports_by_dp[port.stack['dp']].append(port)
            for ports in ports_by_dp.values():
                remote_away_ports = self.stack.canonical_up_ports(
                    [port.stack['port'] for port in ports])
                self.pruned_away_ports.update([
                    port.stack['port'] for port in remote_away_ports
                    if port != remote_away_ports[0]])

        return self.chosen_towards_ports

    def update_stack_topo(self, event, dp, port):
        """
        Update the stack topo according to the event.

        Args:
            event (bool): True if the port is UP
            dp (DP): DP object
            port (Port): The port being brought UP/DOWN
        """
        self.stack.modify_link(dp, port, event)
        towards_ports = self.reset_peer_distances()
        if towards_ports:
            self.logger.info('shortest path to root is via %s' % towards_ports)
        else:
            self.logger.info('no path available to root')

    def default_port_towards(self, dp_name):
        """
        Default shortest path towards the provided destination, via direct shortest path

        Args:
            dp_name (str): Destination DP
        Returns:
           Port: port from current node that is shortest directly towards destination
        """
        return self.stack.shortest_path_port(dp_name)

    def relative_port_towards(self, dp_name):
        """
        Returns the shortest path towards provided destination, via either the root or away paths

        Args:
            dp_name (str): Destination DP
        Returns:
            Port: port from current node that is towards/away the destination DP depending on
                relative position of the current node
        """
        if not self.stack.shortest_path_to_root():
            # No known path from current node to root, use default
            return self.default_port_towards(dp_name)
        if self.stack.name == dp_name:
            # Current node is the destination node, use default
            return self.default_port_towards(dp_name)
        path_to_root = self.stack.shortest_path_to_root(dp_name)
        if path_to_root and self.stack.name in path_to_root:
            # Current node is a transit node between root & destination, direct path to destination
            away_dp = path_to_root[path_to_root.index(self.stack.name) - 1]
            for port in self.away_ports:
                if port.stack['dp'].name == away_dp and not self.is_pruned_port(port):
                    return port
            return None
        # Otherwise, head towards the root, path to destination via root
        return self.chosen_towards_port

    def edge_learn_port_towards(self, pkt_meta, edge_dp):
        """
        Returns the port towards the edge DP

        Args:
            pkt_meta (PacketMeta): Packet on the edge DP
            edge_dp (DP): Edge DP that received the packet
        Returns:
            Port: Port towards the edge DP via some stack chosen metric
        """
        if pkt_meta.vlan.edge_learn_stack_root:
            return self.relative_port_towards(edge_dp.name)
        return self.default_port_towards(edge_dp.name)

    def tunnel_outport(self, src_dp, dst_dp, dst_port):
        """
        Returns the output port for the current stack node for the tunnel path

        Args:
            src_dp (str): Source DP name of the tunnel
            dst_dp (str): Destination DP name of the tunnel
            dst_port (int): Destination port of the tunnel
        Returns:
            int: Output port number for the current node of the tunnel
        """
        if not self.stack.is_in_path(src_dp, dst_dp):
            # No known path from the source to destination DP, so no port to output
            return None
        out_port = self.default_port_towards(dst_dp)
        if self.stack.name == dst_dp:
            # Current stack node is the destination, so output to the tunnel destination port
            out_port = dst_port
        elif out_port:
            out_port = out_port.number
        return out_port

    def update_health(self, now, last_live_times, update_time):
        """
        Returns whether the current stack node is healthy, a healthy stack node
            is one that attempted connected recently, or was known to be running
            recently, has all LAGs UP and any stack port UP

        Args:
            now (float): Current time
            last_live_times (dict): Last live time value for each DP
            update_time (int): Stack root update interval time
        Returns:
            bool: True if current stack node is healthy
        """
        prev_health = self.stack.dyn_healthy_info
        new_health, reason = self.stack.update_health(
            now, last_live_times, update_time)
        if prev_health != self.stack.dyn_healthy_info:
            health = 'HEALTHY' if new_health else 'UNHEALTHY'
            self.logger.info('Stack node %s %s (%s)' % (self.stack.name, health, reason))
        return new_health

    @staticmethod
    def nominate_stack_root(root_valve, other_valves, now, last_live_times, update_time):
        """
        Nominate a new stack root

        Args:
            root_valve (Valve): Previous/current root Valve object
            other_valves (list): List of other valves (not including previous root)
            now (float): Current time
            last_live_times (dict): Last live time value for each DP
            update_time (int): Stack root update interval time
        Returns:
            str: Name of the new elected stack root
        """
        stack_valves = {valve for valve in other_valves if valve.dp.stack}
        if root_valve:
            stack_valves = {root_valve}.union(stack_valves)

        # Create lists of healthy and unhealthy root candidates
        healthy_valves = []
        unhealthy_valves = []
        for valve in stack_valves:
            if valve.dp.stack.is_root_candidate():
                healthy = valve.stack_manager.update_health(now, last_live_times, update_time)
                if healthy:
                    healthy_valves.append(valve)
                elif valve.dp.stack.dyn_healthy_info[0]:
                    unhealthy_valves.append(valve)

        if not healthy_valves and not unhealthy_valves:
            # No root candidates/stack valves, so no nomination
            return None

        # Choose a candidate valve to be the root
        if healthy_valves:
            # Healthy valves exist, so pick a healthy valve as root
            new_root_name = None
            if root_valve:
                new_root_name = root_valve.dp.name
            if root_valve not in healthy_valves:
                # Need to pick a new healthy root if current root not healthy
                stacks = [valve.dp.stack for valve in healthy_valves]
                _, new_root_name = stacks[0].nominate_stack_root(stacks)
        else:
            # No healthy stack roots, so forced to choose a bad root
            new_root_name = None
            if root_valve:
                # Current root is unhealthy along with all other roots, so keep root the same
                new_root_name = root_valve.dp.name
            if root_valve not in unhealthy_valves:
                # Pick the best unhealthy root
                stacks = [valve.dp.stack for valve in unhealthy_valves]
                _, new_root_name = stacks[0].nominate_stack_root(stacks)

        return new_root_name

    def consistent_roots(self, expected_root_name, valve, other_valves):
        """Returns true if all the stack nodes have the root configured correctly"""
        stacked_valves = {valve}.union(self.stacked_valves(other_valves))
        for stack_valve in stacked_valves:
            if stack_valve.dp.stack.root_name != expected_root_name:
                return False
        return True

    def stack_ports(self):
        """Yield the stack ports of this stack node"""
        for port in self.stack.ports:
            yield port

    @staticmethod
    def is_stack_port(port):
        """Return whether the port is a stack port"""
        return bool(port.stack)

    def is_away(self, port):
        """Return whether the port is an away port for the node"""
        return port in self.away_ports

    def is_towards_root(self, port):
        """Return whether the port is a port towards the root for the node"""
        return port in self.towards_root_ports

    def is_selected_towards_root_port(self, port):
        """Return true if the port is the chosen towards root port"""
        return port == self.chosen_towards_port

    def is_pruned_port(self, port):
        """Return true if the port is to be pruned"""
        if self.is_towards_root(port):
            return not self.is_selected_towards_root_port(port)
        if self.is_away(port):
            if self.pruned_away_ports:
                return port in self.pruned_away_ports
            return False
        return True

    def adjacent_stack_ports(self, peer_dp):
        """Return list of ports that connect to an adjacent DP"""
        return [port for port in self.stack.ports if port.stack['dp'] == peer_dp]

    def acl_update_tunnel(self, acl):
        """Return ofmsgs for all tunnels in an ACL with a tunnel rule"""
        ofmsgs = []
        source_vids = defaultdict(list)
        for _id, tunnel_dest in acl.tunnel_dests.items():
            dst_dp, dst_port = tunnel_dest['dst_dp'], tunnel_dest['dst_port']
            # Update the tunnel rules for each tunnel action specified
            updated_sources = []
            updated_reverse_sources = []
            for source_id, source in acl.tunnel_sources.items():
                # We loop through each tunnel source in a single ACL instance and update the info
                src_dp, src_port = source['dp'], source['port']
                in_port = self.tunnel_outport(
                    dst_dp, src_dp, src_port)
                out_port = self.tunnel_outport(
                    src_dp, dst_dp, dst_port)
                updated = False
                if out_port is None and dst_port is None and dst_dp == self.dp.name:
                    # Will need to update at most once, to ensure the correct rules
                    # get populated in the destination DP for a tunnel that outputs
                    # to just a DP
                    updated = acl.update_source_tunnel_rules(
                        self.stack.name, source_id, _id, out_port, self.output_table)
                elif out_port:
                    updated = acl.update_source_tunnel_rules(
                        self.stack.name, source_id, _id, out_port, self.output_table)
                if updated:
                    if self.stack.name == src_dp:
                        # We need to re-build and apply the whole ACL
                        source_vids[source_id].append(_id)
                    else:
                        # We only need to re-build and apply the tunnel
                        updated_sources.append(source_id)
                reverse_updated = False
                if src_port is None and in_port is None and src_dp == self.dp.name:
                    reverse_updated = acl.update_reverse_tunnel_rules(
                        self.stack.name, source_id, _id, in_port, self.output_table)
                elif in_port:
                    reverse_updated = acl.update_reverse_tunnel_rules(
                        self.stack.name, source_id, _id, in_port, self.output_table)
                if reverse_updated:
                    if acl.requires_reverse_tunnel(_id):
                        # Update the reverse tunnel rules if the tunnel is configured to have them
                        updated_reverse_sources.append(source_id)
            # The tunnel in the ACL does not have a source on this stack instance, so
            #   we only need to re-build the special tunnel forwarding rule.
            for source_id in updated_sources:
                ofmsgs.extend(self.acl_manager.build_tunnel_rules_ofmsgs(
                    source_id, _id, acl))
            for source_id in updated_reverse_sources:
                ofmsgs.extend(self.acl_manager.build_reverse_tunnel_rules_ofmsgs(
                    source_id, _id, acl))
        # If a tunnel is updated, but the source is configured as the current DP
        #   then we will also need to re-build the rest of the ACL rules aswell.
        for source_id, vids in source_vids.items():
            for vid in vids:
                ofmsgs.extend(self.acl_manager.build_tunnel_acl_rule_ofmsgs(
                    source_id, vid, acl))
        return ofmsgs

    def add_tunnel_acls(self):
        """Returns ofmsgs installing the tunnel path rules"""
        ofmsgs = []
        if self.tunnel_acls:
            for acl in self.tunnel_acls:
                ofmsgs.extend(self.acl_update_tunnel(acl))
        return ofmsgs

    def add_port(self, port):
        """Need to add tunnel if port comes up with tunnel ACLs."""
        if not port.stack and port.tunnel_acls():
            return self.add_tunnel_acls()
        return []
