#!/usr/bin/env python3

"""Shows the crash in the FAUCET log produced by given input."""


import sys
from ryu.controller import dpset
from faucet import faucet
import fake_packet


def main():
    """Shows the crash in the FAUCET log produced by given input."""

    with open(sys.argv[1], encoding='utf-8') as pkt:
        packet_data = str(pkt.read())

    # start faucet
    application = faucet.Faucet(dpset=dpset.DPSet())
    application.start()

    # make sure dps are running
    if application.valves_manager is not None:
        for valve in list(application.valves_manager.valves.values()):
            state = valve.dp.dyn_finalized
            valve.dp.dyn_finalized = False
            valve.dp.running = True
            valve.dp.dyn_finalized = state

    # create data from read file
    byte_data = None
    try:
        byte_data = bytearray.fromhex(packet_data)  # pytype: disable=missing-parameter,wrong-arg-types
    except (ValueError, TypeError):
        pass

    if byte_data is not None:
        # create fake packet
        _dp = fake_packet.Datapath(1)
        msg = fake_packet.Message(datapath=_dp, cookie=15243729, port=1, data=byte_data, in_port=1)
        pkt = fake_packet.RyuEvent(msg)

        # send packet to faucet and display error produced
        application.packet_in_handler(pkt)


if __name__ == "__main__":
    # make sure user specifies the afl crash folder
    if len(sys.argv) == 2:
        main()
    else:
        sys.stderr.write('USAGE: python3 display_packet_crash.py <AFL_CRASH_FILE>\n')
