1.7.0
^^^^^

We are making a few potentially breaking features in faucet 1.7.0. This document
covers how to navigate the changes and safely upgrade from earlier versions to
1.7.0.

  1. **Configuration and log directory changed**

       Starting in 1.7.0 and onwards faucet has changed which directories it
       uses for configuration and log files. The new paths are:

       ===================  ===============
       Old path             New path
       ===================  ===============
       /etc/ryu/faucet      /etc/faucet
       /var/log/ryu/faucet  /var/log/faucet
       ===================  ===============

       Faucet 1.7.0 when being installed by pip will automatically attempt to
       migrate your old configuration files to ``/etc/faucet`` assuming it has
       permissions to do so. Failing this faucet when started will fallback to
       loading configuration from ``/etc/ryu/faucet``. The search paths for
       configuration files are documented on the :ref:`env-vars` page.

       .. note::
           Consider the ``/etc/ryu/faucet`` directory deprecated, we will in a
           future release stop reading config files stored in this directory.

       If you currently set your own configuration or log directory by setting
       the appropriate environment variables you will be unaffected. In most
       other cases the migration code or the fallback configuration search path
       will allow the upgrade to 1.7.0 to be seamless. We have however
       identified two cases where manual intervention is required:

       **Dockers**

       Dockers will need to be started with new mount directories, the commands
       to start a 1.7.0 docker version of faucet or gauge are detailed in the
       :doc:`docker` section.

       **Virtualenvs**

       We are unable to migrate configuration files automatically when faucet
       is run inside of a virtualenv, please copy the configuration directory
       over manually.

  2. **Changing default flood mode**

       Currently faucet defaults to using ``combinatorial_port_flood`` when it
       comes to provisioning flooding flows on a datapath, faucet implicitly
       configures a datapath like this today:

       .. code:: yaml

           dps:
               mydp:
                   combinatorial_port_flood: True

       The default is ``True``, in 1.7.0 and previously. The default will change
       to ``False`` in 1.7.1.

       When ``True``, flood rules are explicitly generated for each input port,
       to accommodate early switch implementations which (differing from the
       OpenFlow standard - see below) did not discard packets output to the
       packet input port. ``False`` generates rules per faucet VLAN which
       results in fewer rules and better scalability.

       See `OpenFlow 1.3.5 specification <https://www.opennetworking.org/images/stories/downloads/sdn-resources/onf-specifications/openflow/openflow-switch-v1.3.5.pdf>`_, section B.6.3:

       ::

           The behavior of sending out the incoming port was not clearly defined
           in earlier versions of the specification. It is now forbidden unless
           the output port is explicitly set to OFPP_IN_PORT virtual port
           (0xfff8) is set.
