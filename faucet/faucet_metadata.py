PORT_METADATA_MASK = 0xFFF
VLAN_METADATA_MASK = 0xFFF000
EGRESS_METADATA_MASK = PORT_METADATA_MASK | VLAN_METADATA_MASK

def get_egress_metadata(port_num, vid):
    metadata = vid << 12 | (port_num & PORT_METADATA_MASK)
    return metadata, EGRESS_METADATA_MASK
