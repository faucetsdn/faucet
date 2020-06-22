#!/usr/bin/env python3

"""Run AFL repeatedly with externally supplied generated packet from STDIN."""

import logging
import sys

import afl
from ryu.controller import dpset
from faucet import faucet
import fake_packet

ROUNDS = 1
logging.disable(logging.CRITICAL)


def main():
    """Run AFL repeatedly with externally supplied generated packet from STDIN."""
    application = faucet.Faucet(dpset=dpset.DPSet())
    application.start()

    # make sure dps are running
    if application.valves_manager is not None:
        for valve in list(application.valves_manager.valves.values()):
            state = valve.dp.dyn_finalized
            valve.dp.dyn_finalized = False
            valve.dp.running = True
            valve.dp.dyn_finalized = state

    while afl.loop(ROUNDS):  # pylint: disable=c-extension-no-member
        # receive input from afl
        rcv = sys.stdin.read()
        data = None
        try:
            data = bytearray.fromhex(rcv)  # pytype: disable=missing-parameter,wrong-arg-types
        except (ValueError, TypeError):
            continue

        # create fake packet
        _dp = fake_packet.Datapath(1)
        msg = fake_packet.Message(datapath=_dp, cookie=15243729, port=1, data=data, in_port=1)
        pkt = fake_packet.RyuEvent(msg)

        # send fake packet to faucet
        application.packet_in_handler(pkt)


if __name__ == "__main__":
    main()
