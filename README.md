# faucetTutorial

Note: this tutorial is work in progress.

Start with [Installing faucet for the first time](https://faucet.readthedocs.io/en/latest/tutorials.html)
which brad will be demonstrating in the morning. acls carries directly on from that.

Then:
1. [ACLs](ACLs.md)
2. [VLANs](vlan_tutorial.md)
3. [Routing](routing.md)
4. [NFV services](nfv-services-tutorial.md)


If comfortable with the above topics [Build your own network](byon.md)



THe VM will need to have already installed:
- ssh
- wireshark /TCPDump
- Iperf3
- Docker?
- Firefox
- Ovs bash completion scripts.
- Bird (required dependencies to build: flex bison libncurses5-dev libreadline-dev)
- screen/tmux

(user will install faucet & ovs from brad's repo as part of first time tutorial).

Those set up scripts (create_ns, as_ns, clear_ns, cleanup) could be placed in the bashrc.
Basic vim config for spaces not tabs.
