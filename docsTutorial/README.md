# faucetTutorial

Note: this tutorial is work in progress.

Eventually this repository will be moved into the faucet docs website where the rst files will be compiled to html.
So some of the yaml code blocks are not rendered while viewing on github.
As a temporary workaround view the rst as a 'raw'.
Or download the \_build folder which contains the generated html file.


Start with [Installing faucet for the first time](https://faucet.readthedocs.io/en/latest/tutorials.html)
which brad will be demonstrating in the morning. acls carries directly on from that.

Then:
1. [ACLs](ACLs.rst)
2. [VLANs](vlan_tutorial.rst)
3. [Routing](routing.rst)
4. [NFV services](nfv-services-tutorial.rst)
5. [Routing 2](routing-2.rst)


If comfortable with the above topics [Build your own network](byon.rst)



THe VM will need to have already installed:
- ssh
- wireshark /TCPDump
- Iperf3
- Docker?
- Firefox
- Ovs bash completion scripts.
- Bird
- screen/tmux

username/password: ubuntu/ubuntu

(user will install faucet & ovs from brad's repo as part of first time tutorial).

Those set up scripts (create_ns, as_ns, clear_ns, cleanup) could be placed in the bashrc.
Basic vim config for spaces not tabs.



To build the html (on ecs machine)

run
```bash
pip3 install --user -r requirements.txt
make html
```
