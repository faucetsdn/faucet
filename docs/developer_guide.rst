Developer Guide
===============

This file contains an overview of architecture, coding design/practices,
testing and style.

Before submitting a PR
----------------------

-  If you have general questions, feel free to reach out to the faucet-dev mailing list.
-  If you are new to FAUCET, or are contemplating a major change, it's recommended to
   open a github issue with the proposed change. This will enable broad understanding of
   your work including being able to catch any potential snags very early (for example,
   adding new dependencies). Architectural and approach questions are best
   settled at this stage before any code is written.
-  Please send relatively small, tightly scoped PRs (approx 200-300 LOC or less).
   This makes review and analysis easier and lowers risk, including risk of merge
   conflicts with other PRs. Larger changes must be refactored into incremental changes.
-  You must add a test if FAUCET's functionality changes (ie. a new
   feature, or correcting a bug).
-  All unit and integration tests must pass (please use the docker based tests; see
   :ref:`docker-sw-testing`). Where hardware is available, please also run the hardware
   based integration tests also.
-  In order to speed up acceptance of your PR we recommend enabling TravisCI on your
   own github repo, and linking the test results in the body of the PR. This enables
   the maintainers to quickly verify that your changes pass all tests in a pristine
   environment while conserving our TravisCI resources on the main branch (by minimizing
   resources used on potentially failing test runs which could be caught before opening
   a PR on the main branch).
-  You must use the github feature branches (see https://gist.github.com/vlandham/3b2b79c40bc7353ae95a),
   for your change and squash commits (https://blog.github.com/2016-04-01-squash-your-commits/)
   when creating the PR.
-  Please use the supplied git pre-commit hook (see ``../git-hook/pre-commit``),
   to automatically run the unit tests and pylint for you at git commit time,
   which will save you TravisCI resources also.
-  pylint must show no new errors or warnings.
-  Code must conform to the style guide (see below).

PR handling guidelines
----------------------

This section documents general guidelines for the maintainers in handling PRs.
The overall intent is, to enable quality contributions with as low overhead as possible,
maximizing the use of tools such as static analysis and unit/integration testing,
and supporting rapid and safe advancement of the overall project.

In addition to the above PR submission guidelines, above:

-  PRs require a positive review per github's built in gating feature. The approving
   reviewer executes the merge.
-  PRs that should not be merged until some other criteria are met (e.g. not
   until release day) must include DO NOT MERGE in the title, with the details
   in PR comments.
-  A typical PR review/adjust/merge cycle should be 2-3 days (timezones, weekends, etc
   permitting). If a PR upon review appears too complex or requires further
   discussion it is recommended it be refactored into smaller PRs or
   discussed in another higher bandwidth forum (e.g. a VC) as appropriate.
-  A PR can be submitted at any time, but to simplify release logistics PR merges
   might not be done before release, on release days.


Code style
----------

Please use the coding style documented at
https://github.com/google/styleguide/blob/gh-pages/pyguide.md. Existing code not using
this style will be incrementally migrated to comply with it. New code
should comply.

Faucet Development Environment
------------------------------

A common way of developing faucet is inside a `virtualenv <https://virtualenv.pypa.io>`_
with an IDE such as `PyCharm <https://www.jetbrains.com/pycharm/>`_.

Instructions on setting up PyCharm for developing faucet are below.

If you would rather develop on the command line directly, a short summary
of the command line setup for development in a ``venv`` with Python 3.7+
is included after the PyCharm instructions.

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

Inside the PyCharm editor window if we open one of the code files for faucet
(e.g. faucet/faucet.py) we should now get a bar at the top of the window
telling us of missing package requirements, click the ``Install requirements``
option to install the dependencies for faucet.

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

If you are using the sample configuration "as is" you will also need to copy
``/Dev/faucet/etc/faucet/acls.yaml`` to ``/Dev/faucet/venv/etc/faucet/`` as
that included by the sample ``faucet.yaml`` file, and without it the sample
``faucet.yaml`` file cannot be loaded.

You may also wish to copy
``/Dev/faucet/etc/faucet/ryu.conf`` to ``/Dev/faucet/venv/etc/faucet/`` as
well so everything can be referenced in one directory inside the Python
virtual environment.


Configure PyCharm to run faucet and gauge
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now we need to configure PyCharm to run faucet, gauge and the unit tests.

First, click the ``Run -> Run..`` menu, then select the
``Edit Configurations...`` option to get to the build settings dialog.

We will now add run configuration for starting ``faucet`` and ``gauge``.
Click the ``+`` button in the top left hand corner of the window. First, change
the name from ``Unnamed`` to ``faucet``. Change the ``Script path`` to point to
ryu-manager inside the virtualenv, for me this was ``../venv/bin/ryu-manager``.
Then set the ``Parameters`` to ``faucet.faucet``. Make sure the working
directory is set to ``/Dev/faucet/faucet/``.

We will use the same steps as above to add a run configuration for ``gauge``.
Changing the ``Script path`` to ``../venv/bin/ryu-manager`` and setting the
``Parameters`` this time to ``faucet.gauge``. Make sure the working directory is
set to ``/Dev/faucet/faucet/``.

Configure PyCharm to run unit tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For running tests we need a few additional dependencies installed, I
couldn't work out how to do this through PyCharm so run this command from a
terminal window to install the correct dependencies inside the virtualenv:

    .. code:: console

       /Dev/faucet/venv/bin/pip3 install -r /Dev/faucet/test-requirements.txt

To add the test run configuration we will again click the ``+`` button in the
top left hand corner, select ``Python tests -> Unittests``.
You can provide a ``Name`` of ``Faucet Unit Tests`` for the run configuration.
For ``Target`` select ``Script path`` and enter the path
``/Dev/faucet/tests/unit/faucet``. For ``Pattern`` enter ``test_*.py``.

We will also add test run configuration for gauge using the same steps as above.
Use ``Gauge Unit Tests`` as the ``Name`` and for ``Target`` select
``Script path`` and enter the path ``/Dev/faucet/tests/unit/gauge``.
For ``Pattern`` enter ``test_*.py``.

You can click ``Apply`` and ``Close`` now that we've added all our new
run configuration.

Now that everything is setup you can run either the faucet controller, gauge
controller and test suite from the ``Run`` menu.

Developing with a Python 3.7+ venv
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you would prefer not to use PyCharm and are comfortable developing
Python directly on the command line, these steps should get you started.
They have been tested with Ubuntu 18.04 LTS, which includes Python 3.7,
but similar instructions should work on other platforms that include
Python 3.7+.

Install C/C++ compilers and Python development environment packages:

    .. code:: console

       sudo apt-get install python3-venv libpython3.7-dev gcc g++ make

If you have not already, clone the faucet git repository:

    .. code:: console

       git clone https://github.com/faucetsdn/faucet.git

Then create a Python ``venv`` environment within it:

    .. code:: console

       cd faucet
       python3 -m venv "${PWD}/venv"

and activate that virtual environment for all following steps:

    .. code:: console

       . venv/bin/activate

Ensure that the faucet config is present within the virtual environment,
copying from the default config files if required:

    .. code:: console

       mkdir -p "${VIRTUAL_ENV}/var/log/faucet"
       mkdir -p "${VIRTUAL_ENV}/etc/faucet"

       for FILE in {acls,faucet,gauge}.yaml ryu.conf; do
         if [ -f "${VIRTUAL_ENV}/etc/faucet/${FILE}" ]; then
           echo "Preserving existing ${FILE}"
         else
           echo "Installing template ${FILE}"
           cp -p "etc/faucet/${FILE}" "${VIRTUAL_ENV}/etc/faucet/${FILE}"
         fi
       done

Then install the runtime and development requirements

    .. code:: console

       "${VIRTUAL_ENV}/bin/pip3" install wheel   # For bdist_wheel targets
       "${VIRTUAL_ENV}/bin/pip3" install -r "${VIRTUAL_ENV}/../test-requirements.txt"

Finally install faucet in an editable form:

    .. code:: console

       pip install -e .

And then confirm that you can run the unit tests:

    .. code:: console

       pytest tests/unit/faucet/
       pytest tests/unit/gauge/


Makefile
--------

Makefile is provided at the top level of the directory.  Output of ``make``
is normally stored in ``dist`` directory. The following are the targets that
can be used:

 - **uml**: Uses ``pyreverse`` to provide code class diagrams.
 - **codefmt**: Provides command line usage to "Code Style" the Python file
 - **codeerrors**: Uses ``pylint`` on all Python files to generate a code error report and is placed in ``dist`` directory.
 - **stats**: Provides a list of all commits since the last release tag.
 - **release**: Used for releasing FAUCET to the next version, Requires ``version`` and ``next_version`` variables.

To *directly install* faucet from the cloned git repo, you could use ``sudo python setup.py install`` command from the root of the directory.

To *build pip installable package*, you could use ``python setup.py sdist`` command from the root of the directory.

To *remove* any temporarily created directories and files, you could use ``rm -rf dist *egg-info`` command.


Building Documentation
~~~~~~~~~~~~~~~~~~~~~~

The documentation is built with Sphinx, from within the ``docs`` directory.

To be able to build the documentation ensure you have the relevant packages
installed:

    .. code:: console

       cd docs
       sudo apt-get install librsvg2-bin make
       pip3 install -r requirements.txt

and then you can build HTML documentation with:

    .. code:: console

       cd docs
       make html

and the documentation will be found under ``_build/html`` in the ``docs``
directory.


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
