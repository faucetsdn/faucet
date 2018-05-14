Build Your Own Network
======================

If you are already familar with Faucet or want a challenge, dive into the `configuration documentation <https://docs.faucet.nz/en/latest/configuration.html>`_ and build a subset of your network with Faucet.

Prerequisites:
--------------

- Faucet - `Package installation steps 1 & 2 <https://faucet.readthedocs.io/en/latest/tutorials.html#package-installation>`__
- OpenVSwitch - `Connect your first datapath steps 1 & 2 <https://faucet.readthedocs.io/en/latest/tutorials.html#connect-your-first-datapath>`__
- Useful Bash Functions

.. literalinclude:: _static/tutorial/create_ns


.. literalinclude:: _static/tutorial/as_ns

.. literalinclude:: _static/tutorial/cleanup

To make these functions persistent between sessions add them to the bottom of your .bashrc and run 'source .bashrc'.

Example
-------

Ideas:

- Stacking
- BGP Peering
- Event System
