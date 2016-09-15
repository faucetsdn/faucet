
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser


def apply_actions(actions):
    return parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)

def goto_table(table_id):
    return parser.OFPInstructionGotoTable(table_id)

def set_eth_src(eth_src):
    return parser.OFPActionSetField(eth_src=eth_src)

def set_eth_dst(eth_dst):
    return parser.OFPActionSetField(eth_dst=eth_dst)

def push_vlan_act(vlan_vid):
    return [
        parser.OFPActionPushVlan(ether.ETH_TYPE_8021Q),
        parser.OFPActionSetField(vlan_vid=(vlan_vid | ofp.OFPVID_PRESENT))
    ]

def dec_ip_ttl():
    return parser.OFPActionDecNwTtl()

def packetout(out_port, data):
    return parser.OFPPacketOut(
        datapath=None,
        buffer_id=ofp.OFP_NO_BUFFER,
        in_port=ofp.OFPP_CONTROLLER,
        actions=[parser.OFPActionOutput(out_port, 0)],
        data=data)
