#!/usr/bin/env python3

"""Shows the crash in the FAUCET log produced by given input."""


import sys
from ryu.controller import dpset
from faucet import faucet
from faucet import faucet_experimental_api
import Fake


def main():
    # go through all files in directory
    # read file and store in string
    with open(sys.argv[1]) as pkt:
        packet_data = str(pkt.read())

    # start faucet
    application = faucet.Faucet(
        dpset=dpset.DPSet(),
        faucet_experimental_api=faucet_experimental_api.FaucetExperimentalAPI())
    application.start()

    # make sure dps are running
    if application.valves_manager is not None:
        for valve in list(application.valves_manager.valves.values()):
            valve.dp.running = True

    # create data from read file
    byte_data = None
    try:
        byte_data = bytearray.fromhex(packet_data) # pytype: disable=missing-parameter
    except (ValueError, TypeError):
        pass

    if byte_data is not None:
        # create fake packet
        dp = Fake.Datapath(1)
        msg = Fake.Message(datapath=dp, cookie=1524372928, port=1, data=byte_data, in_port=1)
        pkt = Fake.RyuEvent(msg)

        # send packet to faucet and display error produced
        application.packet_in_handler(pkt)


if __name__ == "__main__":
    # make sure user specifies the afl crash folder
    if len(sys.argv) == 2:
        main()
    else:
        print('USAGE: python3 display_packet_crash.py <AFL_CRASH_FILE>')
