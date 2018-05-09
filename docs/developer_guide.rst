Developer Guide
===============

This file contains an overview of architecture, coding design/practices,
testing and style.

Before submitting a PR
----------------------

-  All unit and integration tests must pass (please use the docker based tests; see
   :ref:`docker-sw-testing`).
-  You must add a test if FAUCET's functionality changes (ie. a new
   feature, or correcting a bug).
-  Please use the supplied git pre-commit hook (see ``../git-hook/pre-commit``),
   to automatically run the unit tests and pylint for you at git commit time.
-  Please enable TravisCI testing on your repo, which enables the maintainers
   to quickly verify that your changes pass all tests in a pristine environment.
-  pylint must show no new errors or warnings.
-  Code must conform to the style guide (see below).

Code style
----------

Please use the coding style documented at
http://google.github.io/styleguide/pyguide.html. Existing code not using
this style will be incrementally migrated to comply with it. New code
should comply.

Faucet Development Environment
------------------------------

A common way of developing faucet is inside a `virtualenv <https://virtualenv.pypa.io>`_
with an IDE such as `PyCharm <https://www.jetbrains.com/pycharm/>`_.

Instructions on setting up PyCharm for developing faucet are as follows:

Create a new project in PyCharm
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set the ``Location`` of the project to the directory where a checked out
copy of the faucet code from git is, for this tutorial I will assume the
path is ``/Dev/faucet/``.

Ignore the ``Project Interpreter`` settings for now, we will set those up
after the project is created.

Click ``Create`` when you have completed these steps.

When asked ``Would you like to create a project from existing sources instead?``
click ``Yes``.

Create virtual environment
~~~~~~~~~~~~~~~~~~~~~~~~~~

Now that the project is created and source code imported, click the
``File -> Settings`` menu. In the dialog box that opens click the
``Project: faucet -> Project Interpreter`` sub menu.

Click the cog and select ``Add...``

Under ``Virtualenv Environment`` you want to select ``New environment`` and
select a ``Location`` for the virtualenv (which can be inside the directory
where the faucet code lives, e.g ``/Dev/faucet/venv``).

The ``Base interpreter`` should be set to /usr/bin/python3.

Click ``Ok`` which will create the virtualenv.

Now while that virtualenv builds and we still have the settings dialog open
we will tweak a few project settings to make them compatible with our
code style. Click on the ``Tools -> Python Integrated Tools`` menu
and change the ``Docstring format`` to ``Google``.

Finally, click ``Ok`` again to get back to the main screen of PyCharm.

Install requirements
~~~~~~~~~~~~~~~~~~~~

Inside the PyCharm editor window we should now get a bar at the top of the
window telling us of missing package requirements, click the
``Install requirements`` option to install the dependencies for faucet.

Create log and configuration directories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now we need to create a log and configuration directory so that faucet
can start:

    .. code:: console

       mkdir -p /Dev/faucet/venv/var/log/faucet/
       mkdir -p /Dev/faucet/venv/etc/faucet/

Copy the sample faucet configuration file from
``/Dev/faucet/etc/faucet/faucet.yaml`` to ``/Dev/faucet/venv/etc/faucet/`` and
edit this configuration file as necessary.

Copy the sample gauge configuration file from
``/Dev/faucet/etc/faucet/gauge.yaml`` to ``/Dev/faucet/venv/etc/faucet/`` and
edit this configuration file as necessary.

Configure PyCharm to run faucet
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now we need to configure PyCharm to run faucet, gauge and the unit tests.

First, click the ``Run -> Run..`` menu, then select the
``Edit Configurations...`` option to get to the build settings dialog.

We will edit the default ``faucet`` run configuration that has been created
for us. First change the ``Script path`` to point to ryu-manager inside the
virtualenv, for me this was ``../venv/bin/ryu-manager``. Then set the
``Parameters`` to ``faucet.faucet``. Make sure the working directory is
set to ``/Dev/faucet/faucet/``.

We will also add a ``gauge`` run configuration for starting gauge.
First change the ``Script path`` to point to ryu-manager inside the
virtualenv, for me this was ``../venv/bin/ryu-manager``. Then set the
``Parameters`` to ``faucet.gauge``. Make sure the working directory is
set to ``/Dev/faucet/faucet/``.

For running tests we need a few additional dependencies installed, I
couldn't work out how to do this through PyCharm so run this command from a
terminal window to install the correct dependencies inside the virtualenv:

    .. code:: console

       /Dev/faucet/venv/bin/pip3 install -r /Dev/faucet/test-requirements.txt

Click the green plus icon to add a new build configuration, select
``Python tests -> Unittests``. You can provide a ``Name`` of
``Faucet Unit Tests`` for the run configuration. For ``Target`` select
``Script path`` and enter the path ``/Dev/faucet/tests``. For ``Pattern``
enter ``test_*.py``.

You can click ``Apply`` and ``Close`` now that we've added all our new
run configuration.

Now that everything is setup you can run either the faucet controller, gauge
controller and test suite from the ``Run`` menu.

Makefile
--------

Makefile is provided at the top level of the directory.  Output of ``make``
is normally stored in ``dist`` directory. The following are the targets that
can be used:

 - **uml**: Uses ``pyreverse`` to provide code class diagrams.
 - **dot**: Uses ``dot`` to provide hirearchical representation of ``faucet.yaml`` based on ``docs/images/faucet-yaml.dot`` file
 - **codefmt**: Provides command line usage to "Code Style" the Python file
 - **codeerrors**: Uses ``pylint`` on all Python files to generate a code error report and is placed in ``dist`` directory.
 - **stats**: Provides a list of all commits since the last release tag.
 - **release**: Used for releasing FAUCET to the next version, Requires ``version`` and ``next_version`` variables.

To *directly install* faucet from the cloned git repo, you could use ``sudo python setup.py install`` command from the root of the directory.

To *build pip installable package*, you could use ``python setup.py sdist`` command from the root of the directory.

To *remove* any temporarily created directories and files, you could use ``rm -rf dist *egg-info`` command.


Key architectural concepts/assumptions:
---------------------------------------

FAUCET's architecture depends on key assumptions, which must be kept in
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

FAUCET depends upon these assumptions to guarantee that the switch is
always in a known and consistent state, which in turn is required to
support high availability (FAUCET provides high availability, through
multiple FAUCET controllers using the same version of configuration -
any FAUCET can give the switch a consistent response - no state sharing
between controllers is required). The FAUCET user can program customized
flows to be added to the switch using FAUCET ACLs (see below).

FAUCET also programs the dataplane to do flooding (where configured).
This minimizes the use of packet in. This is necessary to reduce
competition between essential control plane messages (adding and
removing flows), and traffic from the dataplane on the limited bandwidth
OpenFlow control channel. Unconstrained packet in messages impact the
switch CPU, may overwhelm the OpenFlow control channel, and will expose
the FAUCET controller to unvalidated dataplane packets, all of which are
security and reliability concerns. In future versions, packet in will be
eliminated altogether. The FAUCET user is expected to use policy based
forwarding (eg ACLs that redirect traffic of interest to high
performance dataplane ports for NFV offload), not packet in.

FAUCET requires all supported dataplanes to implement OpenFlow
(specifically, a subset of OpenFlow 1.3) in a functionally identical
way. This means that there is no switch-specific driver layer - the
exact same messages are sent, whether the switch is OVS or hardware.
While this does prevent some earlier generation OpenFlow switches from
being supported, commercially available current hardware does not have
as many restrictions, and eliminating the need for a switch-specific (or
TTP) layer greatly reduces implementation complexity and increases
controller programmer productivity.
