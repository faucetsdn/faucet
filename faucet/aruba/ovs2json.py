#!/usr/bin/env python
#
# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Convert output of ovs-ofctl/dpctl dump-flows into pipeline JSON which
    would support those flows on an HPE Aruba switch. If the set of flows
    cannot fit into a possible pipeline within the HPE Aruba switch, one
    or more errors will be generated to indicate the reason. """

import sys
import re
import os
import json

# =========================== Match Field Data ================================

# This tool is coded according to the "Flow Syntax" section of the following
# OVS documentation:
#   http://openvswitch.org/support/dist-docs/ovs-ofctl.8.txt

# Match fields are keyed to the group they correspond with.
# Those fields which are their own group are given high numbers.
OVS_MATCH_FIELDS = {
    # Basic OF match fields
    'in_port':4, 'dl_vlan':4, 'dl_vlan_pcp':4,
    'dl_src':1, 'dl_dst':1, 'dl_type':1,
    'nw_src':2, 'nw_dst':3,
    'nw_proto':4, 'ip_proto':4, 'ip_dscp':4,
    'tcp_src':4, 'tcp_dst':4, 'udp_src':4, 'udp_dst':4,
    'tcp_flags':899, 'icmp_type':900, 'icmp_code':901,
    # Nicira extensions
    'arp_op':902, 'arp_spa':903, 'arp_tpa':904, 'arp_sha':905, 'arp_tha':906,
    'ipv6_src':2, 'ipv6_dst':3, 'ipv6_label':907, 'nd_target':908}

# Match fields which are not supported by HPE Aruba switches,
# regardless of the pipeline configuration.
OVS_UNSUPPORTED_MATCH = [
    # Basic OF match fields
    'nw_tos', 'nw_ttl', 'nw_ecn', 'ip_ecn',
    'sctp_src', 'sctp_dst', 'metadata',
    # Nicira extensions
    'vlan_tci', 'ip_frag', 'nd_sll', 'nd_tll',
    'mpls_bos', 'mpls_label', 'mpls_tc',
    'tun_id', 'tunnel_id', 'tun_flags', 'tun_src', 'tun_dst',
    'tun_ipv6_src', 'tun_ipv6_dst', 'tun_gbp_id', 'tun_gbp_flags',
    'tun_metadataidx', 'regidx', 'xregidx', 'pkt_mark', 'actset_output',
    'conj_id', 'ct_state', 'ct_zone', 'ct_mark', 'ct_label']

OVS_KNOWN_MATCH = set(OVS_MATCH_FIELDS.keys()).union(set(OVS_UNSUPPORTED_MATCH))

# OVS match abbreviations, keyed to what they abbreviate
OVS_MATCH_ABBREV = {
    'ip': 'dl_type=0x0800',
    'ipv6': 'dl_type=0x86dd',
    'icmp': 'dl_type=0x0800,nw_proto=1',
    'icmp6': 'dl_type=0x86dd,nw_proto=58',
    'tcp': 'dl_type=0x0800,nw_proto=6',
    'tcp6': 'dl_type=0x86dd,nw_proto=6',
    'udp': 'dl_type=0x0800,nw_proto=17',
    'udp6': 'dl_type=0x86dd,nw_proto=17',
    'sctp': 'dl_type=0x0800,nw_proto=132',
    'sctp6': 'dl_type=0x86dd,nw_proto=132',
    'arp': 'dl_type=0x0806',
    'rarp': 'dl_type=0x8035',
    'mpls': 'dl_type=0x8847',
    'mplsm': 'dl_type=0x8848',
    # Assume deprecated tp_src/dst are UDP (to avoid complicated parsing)
    'tp_src': 'udp_src',
    'tp_dst': 'udp_dst',
    # Special case use of vlan_tci to match packets without a VLAN tag,
    # to dl_vlan=0. Per OF1.3.3 spec p.117:
    #   - Testing for an exact match with 0x0 matches only packets without
    #   * an 802.1Q header.
    'vlan_tci=0x0000/0x1fff': 'dl_vlan=0'}

# Conversion from OVS field name to RYU field name. Keys should be identical
# to the keys in OVS_MATCH_FIELDS.
JSON_FIELDS = {
    # Basic OF match fields
    'in_port':'in_port', 'dl_vlan':'vlan_vid', 'dl_vlan_pcp':'vlan_pcp',
    'dl_src':'eth_src', 'dl_dst':'eth_dst', 'dl_type':'eth_type',
    'nw_src':'ipv4_src', 'nw_dst':'ipv4_dst',
    'nw_proto':'ip_proto', 'ip_proto':'ip_proto', 'ip_dscp':'ip_dscp',
    'tcp_src':'tcp_src', 'tcp_dst':'tcp_dst', 'udp_src':'udp_src', 'udp_dst':'udp_dst',
    'tcp_flags':'tcp_flags', 'icmp_type':'icmpv4_type', 'icmp_code':'icmpv4_code',
    # Nicira extensions
    'arp_op':'arp_op', 'arp_spa':'arp_spa', 'arp_tpa':'arp_tpa', 'arp_sha':'arp_sha', 'arp_tha':'arp_tha',
    'ipv6_src':'ipv6_src', 'ipv6_dst':'ipv6_dst', 'ipv6_label':'ipv6_flabel', 'nd_target':'ipv6_nd_target'}
if sorted(JSON_FIELDS.keys()) != sorted(OVS_MATCH_FIELDS.keys()):
    print('ERROR: Key mismatch between JSON_FIELDS and OVS_MATCH_FIELDS:\n')
    print(set(JSON_FIELDS.keys()).symmetric_difference(set(OVS_MATCH_FIELDS.keys())))
    exit(2)

# Fields which HPE Aruba supports as setfield in any pipeline (keyed with RYU field names, not OVS)
ARUBA_SETFIELDS = [
    'eth_dst', 'eth_src', 'vlan_vid', 'vlan_pcp', 'ip_dscp',
    'ipv4_src', 'ipv4_dst', 'tcp_src', 'tcp_dst', 'udp_src', 'udp_dst']

DEBUG = ('DEBUG' in os.environ)
GENERATE_JSON = True

# =========================== Utility Functions ================================
def debug(arg):
    if DEBUG:
        print(arg)

def error(arg):
    print(arg)
    global GENERATE_JSON
    GENERATE_JSON = False

# =========================== Input Processing ================================

# Check for the input data file
if len(sys.argv) < 2:
    print("Please specify a filename which contains the output of 'ovs-ofctl dump-flows'")
    exit(1)

# Allocate variables which will hold data extracted from OVS output
TABLE_MATCH = {} # Table ID key, value is a list of exact match keys
TABLE_WILDCARDS = {} # Table ID key, value is a list of wildcardable match keys
TABLE_MASKS = {} # Table ID key, value is a list of maskable match keys
TABLE_SIZE = {} # Table ID key, value is number of flows in table

# Iterate over all lines of the file, gathering data
debug("=== Per-flow pipeline analysis ===")
for line in open(sys.argv[1]):
    # Skip empty lines
    line = line.rstrip().lstrip()
    if not line:
        continue

    # debug("FLOW: "+line)
    line_data = re.split(r'\s+', line)
    errors = 0
    table = None
    match = None

    # Identify the table
    for data in line_data:
        if "table=" not in data:
            continue

        # Store the numeric table ID
        table = data.split('=')[1]
        table = re.sub(r'\D', '', table)

    # Identify match criteria
    for data in line_data:
        if "priority=" not in data:
            continue
        match = data

    # Verify that we found both table ID and match data
    if table is None:
        debug("Failed to identify table ID in line:\n "+line)
        continue
    if match is None:
        debug("Failed to identify match data in line:\n "+line)
        continue

    # Handle deprecated tp_src/dst interpretation, which is context-dependent
    if re.match('.*[^c]tp_(src|dst).*', match) != None:
        if "udp" in match or "proto=17" in match:
            match = re.sub(r'([^c]*)tp_(dst|src)', r'\1udp_\2', match)
        else:
            match = re.sub(r'([^c]*)tp_(dst|src)', r'\1tcp_\2', match)

    # Replace abbreviations
    for abbrev in OVS_MATCH_ABBREV:
        fields = match.split(',')
        fields = [re.sub("^"+abbrev+"$", OVS_MATCH_ABBREV[abbrev], f) for f in fields]
        match = ','.join(fields)

    # Get the list of matched and masked fields
    match_keys = set([])
    masks = set([])
    for m in match.split(','):
        # Skip empty match field
        if m == "":
            continue

        # Parse the match key
        mp = m.split('=')
        key = mp[0]
        match_keys.add(key)

        # Parse the match value
        if len(mp) >= 2:
            value = m.split('=')[1]
            if "/" in value:
                masks.add(key)
        else:
            error("Failed to parse special key-value abbreviation: "+str(m))

    match_keys.remove('priority') # Ignore priority, not a match field

    # Verify our hard-coded OVS match fields are complete
    if not OVS_KNOWN_MATCH.issuperset(match_keys):
        error("Attempted to match unknown field(s) "+str(list(match_keys.difference(OVS_KNOWN_MATCH)))+" in flow:\n "+line)
        errors += 1

    # Check unsupported matches
    for unsupp in OVS_UNSUPPORTED_MATCH:
        if unsupp in match_keys:
            error("Match field '"+unsupp+"' is not supported, but was used in:\n "+line)
            errors += 1

    # If we've hit errors, skip this flow because it will complicate the
    # global validation done later.
    if errors > 0:
        continue

    # Increment table size
    if table in TABLE_SIZE:
        TABLE_SIZE[table] += 1
    else:
        TABLE_SIZE[table] = 1
        TABLE_MATCH[table] = set(match_keys)
        TABLE_WILDCARDS[table] = set([])
        TABLE_MASKS[table] = set([])

    # Record match fields
    tm = TABLE_MATCH[table]
    exact = tm.intersection(match_keys)
    wildcard = tm.symmetric_difference(match_keys)
    TABLE_MATCH[table] = set(exact)
    TABLE_WILDCARDS[table] = set(wildcard).union(TABLE_WILDCARDS[table])
    TABLE_MASKS[table] = TABLE_MASKS[table].union(masks)

# Globals used in validation
debug("\n=== Global and per-table pipeline analysis ===")
MAX_SUPPORTED_TABLES = 12
MIN_TCAM_SIZE = 2
MIN_HASH_SIZE = 16
MAX_TCAM_TILES = 8 * 1024
MAX_HASH_TILES = 64 * 1024

# Check if too many tables were used
if len(TABLE_SIZE.keys()) > MAX_SUPPORTED_TABLES:
    error("HPE Aruba switches support a maximum of "+str(MAX_SUPPORTED_TABLES)+" tables, but "+str(len(TABLE_SIZE.keys()))+" were used:\n "+str(TABLE_SIZE.keys()))

# Check if table 0 (required) was used
if '0' not in TABLE_SIZE:
    error("Table 0 was not used, but is required by the OpenFlow specification")

# Get a numerically-sorted list of table IDs
tables = TABLE_SIZE.keys()
tables.sort(key=int)

# Display and analyze gathered data to check for unsupported conditions
tcam_tiles = 0
hash_tiles = 0
for table in tables:
    # Get all fields being matched
    size = TABLE_SIZE[table]
    exact = TABLE_MATCH[table]
    wildcard = TABLE_WILDCARDS[table]
    mask = TABLE_MASKS[table]
    all_matches = exact.union(wildcard).union(mask)

    # Special-case: If a table had flows but none of the flows specified
    # match criteria, we'll specify at least one wildcard (ETH_TYPE) so that
    # the table is considered a TCAM. A hash must have all match fields specified,
    # but since no flows specified match criteria we know a TCAM is expected.
    # Wildcard ETH_TYPE since it is a dependency of many other fields.
    if len(all_matches) == 0:
        TABLE_WILDCARDS[table].add('dl_type')
        wildcard = TABLE_WILDCARDS[table]
        all_matches = exact.union(wildcard).union(mask)

    # Display table data
    debug("TABLE #"+table+" has "+str(size)+" entries")
    if len(exact) > 0:
        debug("  exact-match: "+str(sorted(list(exact))))
    if len(wildcard) > 0:
        debug("  wildcards: "+str(sorted(list(wildcard))))
    if len(mask) > 0:
        debug("  maskable: "+str(sorted(list(mask))))

    # Determine number of match groups
    groups = [OVS_MATCH_FIELDS[m] for m in all_matches]
    groups = set(groups)
    gc = len(groups)

    # Automatically upconvert Hash->TCAM if attempting to match 4 groups in hash
    if len(wildcard) == 0 and len(mask) == 0 and gc == 4:
        wildcard = exact.copy()
        exact.clear()
        debug("  ** Table #"+table+" has been converted from Hash to TCAM, due to matching 4 groups")

    # Calculate resource usage, based on table type
    if len(wildcard) > 0 or len(mask) > 0:
        table_type = "TCAM"
        if gc > 4:
            error("Table #"+table+" attempts to match fields from "+str(gc)+" groups. Maximum of 4 match groups supported in "+table_type)

        if size < MIN_TCAM_SIZE:
            debug("  ** Table #"+table+" has been auto-resized to minimum size of "+str(MIN_TCAM_SIZE))
            size = MIN_TCAM_SIZE

        mult = gc if gc != 3 else 4  # TCAM: 3 groups use same as 4 groups
        tiles = size * mult
        tcam_tiles += tiles
    else:
        table_type = "Hash"
        if gc > 3:
            error("Table #"+table+" attempts to match fields from "+str(gc)+" groups. Maximum of 3 match groups supported in "+table_type)

        if size < MIN_HASH_SIZE:
            debug("  ** Table #"+table+" has been auto-resized to minimum size of "+str(MIN_HASH_SIZE))
            size = MIN_HASH_SIZE

        mult = gc if gc != 3 else 2  # Hash: 3 groups use same as 2 groups
        tiles = size * mult
        hash_tiles += tiles

    # Store any adjusted values
    TABLE_SIZE[table] = size
    TABLE_MATCH[table] = exact
    TABLE_WILDCARDS[table] = wildcard
    TABLE_MASKS[table] = mask

    # Calculate resource allocation for this table
    debug("  allocation: "+str(len(groups))+" groups "+str(list(groups))+" using "+str(tiles)+" "+table_type+" resources")

# Verify that tables will fit into available hardware resources
debug("Total resources:  TCAM={} ({:.2f}%)  Hash={} ({:.2f}%)".format(tcam_tiles, 100*float(tcam_tiles)/MAX_TCAM_TILES,
                                                                      hash_tiles, 100*float(hash_tiles)/MAX_HASH_TILES))
if tcam_tiles > MAX_TCAM_TILES:
    error("Pipeline uses "+str(tcam_tiles)+" TCAM resources. Maximum of "+str(MAX_TCAM_TILES)+" available.")
if hash_tiles > MAX_HASH_TILES:
    error("Pipeline uses "+str(hash_tiles)+" Hash resources. Maximum of "+str(MAX_HASH_TILES)+" available.")

# Exit now if not generating JSON
if not GENERATE_JSON:
    exit(1)

# Generate JSON for RYU pipeline format
debug("\n=== Auto-generated pipeline JSON ===")
prev_tables = set([])
JSON = '['
for table in tables:
    # Get all fields being matched
    size = TABLE_SIZE[table]
    exact = TABLE_MATCH[table]
    wildcard = TABLE_WILDCARDS[table]
    mask = TABLE_MASKS[table]
    all_matches = exact.union(wildcard).union(mask)

    # Table header information
    JSON += '{"max_entries": '+str(size)+','
    JSON += '"name": "Table '+table+'",'
    JSON += '"table_id": '+table+','
    JSON += '"metadata_match": 0,'
    JSON += '"metadata_write": 0,'
    JSON += '"config": 3,'
    JSON += '"properties": ['

    # Matches
    JSON += '{"type":8, "name":"OFPTFPT_MATCH", "oxm_ids": ['
    for m in all_matches:
        hasmask = ""
        if m in mask:
            hasmask = ' , "hasmask": true'
        JSON += '{ "type": "'+JSON_FIELDS[m]+'", "name": "'+JSON_FIELDS[m]+'"'+hasmask+' },'

    # Trim trailing common from last match
    if len(all_matches) > 0:
        JSON = JSON.rstrip(',')
    JSON += ']},'

    # Wildcards
    JSON += '{"type":10, "name": "OFPTFPT_WILDCARDS", "oxm_ids": ['
    for w in wildcard:
        JSON += '{ "type": "'+JSON_FIELDS[w]+'", "name":"'+JSON_FIELDS[w]+'" },'

    # Trim trailing common from last wildcard
    if len(wildcard) > 0:
        JSON = JSON.rstrip(',')
    JSON += ']},'

    # Now that we've generated the match+wildcard criteria, we can assume that
    # all other tables will support all actions, so generate the same action
    # criteria, regardless of what the flows actually tried to use.
    genericSetfields = ['{"type":"'+f+'","name":"'+f+'"}' for f in ARUBA_SETFIELDS]
    genericActions = [
        '{"type":0,"name":"OFPAT_OUTPUT"}',
        '{"type":17,"name":"OFPAT_PUSH_VLAN"}',
        '{"type":18,"name":"OFPAT_POP_VLAN"}',
        '{"type":22,"name":"OFPAT_GROUP"}',
        '{"type":23,"name":"OFPAT_SET_NW_TTL"}',
        '{"type":25,"name":"OFPAT_SET_FIELD"}']
    genericInstructions = [
        '{"type":1,"name":"OFPIT_GOTO_TABLE"}',
        '{"type":3,"name":"OFPIT_WRITE_ACTIONS"}',
        '{"type":4,"name":"OFPIT_APPLY_ACTIONS"}',
        '{"type":5,"name":"OFPIT_CLEAR_ACTIONS"}',
        '{"type":6,"name":"OFPIT_METER"}']
    genericProps = ','.join(
        ['{ "type":0, "name":"OFPTFPT_INSTRUCTIONS", "instruction_ids": [ '+','.join(genericInstructions)+' ] }',
         '{ "type":1, "name":"OFPTFPT_INSTRUCTIONS_MISS", "instruction_ids": [ '+','.join(genericInstructions)+' ] }',
         '{ "type":4, "name":"OFPTFPT_WRITE_ACTIONS", "action_ids": [ '+','.join(genericActions)+' ] }',
         '{ "type":5, "name":"OFPTFPT_WRITE_ACTIONS_MISS", "action_ids": [ '+','.join(genericActions)+' ] }',
         '{ "type":6, "name":"OFPTFPT_APPLY_ACTIONS", "action_ids": [ '+','.join(genericActions)+' ] }',
         '{ "type":7, "name":"OFPTFPT_APPLY_ACTIONS_MISS", "action_ids": [ '+','.join(genericActions)+' ] }',
         '{ "type":12, "name":"OFPTFPT_WRITE_SETFIELD", "oxm_ids": [ '+','.join(genericSetfields)+' ] }',
         '{ "type":13, "name":"OFPTFPT_WRITE_SETFIELD_MISS", "oxm_ids": [ '+','.join(genericSetfields)+' ] }',
         '{ "type":14, "name":"OFPTFPT_APPLY_SETFIELD", "oxm_ids": [ '+','.join(genericSetfields)+' ] }',
         '{ "type":15, "name":"OFPTFPT_APPLY_SETFIELD_MISS", "oxm_ids": [ '+','.join(genericSetfields)+' ] }'])

    # Remove GOTO from last table
    prev_tables.add(table)
    remaining_tables = set(TABLE_SIZE.keys()).difference(prev_tables)
    lastTable = (len(remaining_tables) == 0)
    if lastTable:
        genericProps = ''.join(genericProps.rsplit('{"type":1,"name":"OFPIT_GOTO_TABLE"}, ', 1))
    JSON += genericProps+','

    JSON += '{ "type":2, "name": "OFPTFPT_NEXT_TABLES", "table_ids": [ '+','.join(remaining_tables)+' ] },'
    JSON += '{ "type":3, "name": "OFPTFPT_NEXT_TABLES_MISS", "table_ids": [ '+','.join(remaining_tables)+' ] }'
    JSON += ']}'
    if not lastTable:
        JSON += ','

# Wrap things up and print ...
JSON += ']'

# Pretty-print the condensed JSON string, for easier diffs
jsonobj = json.loads(JSON)
json.dump(jsonobj, sys.stdout, sort_keys=True, indent=4, separators=(',', ': '))
