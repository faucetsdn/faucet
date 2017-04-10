FAUCET developer guide
----------------------

This file contains an overview of architecture, coding design/practices,
testing and style.

Before submitting a PR
~~~~~~~~~~~~~~~~~~~~~~

-  All unit tests must pass (please use the docker based tests; see
   README.docker.md).
-  You must add a test if FAUCET’s functionality changes (ie. a new
   feature, or correcting a bug).
-  pylint must show no new errors or warnings.
-  Code must conform to the style guide (see below).

Code style
~~~~~~~~~~

| Please use the coding style documented at
  http://google.github.io/styleguide/pyguide.html. Existing
| code not using this style will be incrementally migrated to comply
  with it. New code should comply.

Key architectural concepts/assumptions.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

FAUCET’s architecture depends on key assumptions, which must be kept in
mind at all times.

-  FAUCET is the only controller for the switch, that can add or remove
   flows.
-  All supported dataplanes must implement OpenFlow functionally
   (hardware, software or both) identically. No TTP or switch specific
   drivers.

In addition:

-  FAUCET provisions default deny flows (all traffic not explicitly
   programmed is dropped).
-  Use of packet in is minimized.

| FAUCET depends upon these assumptions to gaurantee that the switch is
  always in a known and consistent
| state, which in turn is required to support high availability (FAUCET
  provides high availability, through
| multiple FAUCET controllers using the same version of configuration -
  any FAUCET can give the switch
| a consistent response - no state sharing between controllers is
  required). The FAUCET user can program
| customized flows to be added to the switch using FAUCET ACLs (see
  below).

| FAUCET also programs the dataplane to do flooding (where configured).
  This minimizes the use of packet in.
| This is necessary to reduce competition between essential control
  plane messages (adding and removing flows),
| and traffic from the dataplane on the limited bandwidth OpenFlow
  control channel. Unconstrained packet in messages
| impact the switch CPU, may overwhelm the OpenFlow control channel, and
  will expose the FAUCET controller to
| unvalidated dataplane packets, all of which are security and
  reliability concerns. In future versions
| packet in will be eliminated altogether. The FAUCET user is expected
  to use policy based forwarding
| (eg ACLs that redirect traffic of interest to high performance
  dataplane ports for NFV offload), not packet in.

| FAUCET requires all supported dataplanes to implement OpenFlow
  (specifically, a subset of OpenFlow 1.3)
| in a functionally identical way. This means that there is no
  switch-specific driver layer - the exact same
| messages are sent, whether the switch is OVS or hardware. While this
  does prevent some earlier generation
| OpenFlow switches from being supported, commercially available current
  hardware does not have as many restrictions,
| and eliminating the need for a switch-specific (or TTP) layer greatly
  reduces implementation complexity and
| increases controller programmer productivity.
