Faucet Test tool
------------------------

This tool is to test Faucet functions using OpenFlow 1.3 OpenVSwitch on Mininet.

If you interrupt the test process or it crashes during testing interfaces, processes and openvswitch configuration used for testing
may be left over on the system. You can run the test script in cleanup mode to tidy the system of leftover mininet objects:

```$ sudo ./faucet_mininet_test.py --clean```


Requirement(s)
------------------------
Ryu_faucet

Mininet 2.2.1
