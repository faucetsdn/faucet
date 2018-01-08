#!/usr/bin/env python3
import logging
import os
import sys
import Fake
from faucet import faucet
from ryu.controller import dpset
from faucet import faucet_experimental_api

logging.disable(logging.CRITICAL)

# run faucet
application = faucet.Faucet(dpset=dpset.DPSet(), faucet_experimental_api=faucet_experimental_api.FaucetExperimentalAPI())
application.start()

# make sure dps are running
for dp_id, valve in list(application.valves.items()):
    valve.dp.running = True

import afl
while afl.loop(1000):
    # receive input from afl
    rcv = sys.stdin.read()
    data = None
    try:
        data = bytearray.fromhex(rcv)
    except (ValueError, TypeError):
        pass

    if data is not None:
        # create fake packet
        dp = Fake.Datapath(1)
        msg = Fake.Message(datapath=dp, cookie=1524372928, port=1, data=data, in_port=1)
        pkt = Fake.RyuEvent(msg)

        # send fake packet to faucet
        application.packet_in_handler(pkt)

os._exit(0)