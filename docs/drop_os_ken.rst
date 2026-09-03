Dropping os-ken
===============

Why
---

os-ken is upstream-shedding surface faucet depends on, roughly once per
major release, and each shed has cost us a fix:

===========  =======================================  ====================================
os-ken       What went away                           What it cost us
===========  =======================================  ====================================
3.0          eventlet demoted, native hub added       ``94f01c28``, ``eeab08f9``, and the
                                                      whole block-on-barrier redesign
                                                      (``docs/block_on_barrier.rst``)
4.0          ``os_ken.cmd`` / ``osken-manager``       ``6ce083b2`` -- 300 lines of
                                                      ``faucet/__main__.py`` is now an
                                                      inlined copy of ``cmd/manager.py``
(earlier)    ``os_ken.app.wsgi``                      ``ofctl_rest/wsgi.py`` -- 309 lines
                                                      vendored in tree
===========  =======================================  ====================================

os-ken also drags oslo.config, eventlet, netaddr and packaging into
faucet's runtime dependency tree; faucet needs none of them on their own
merits.

The pattern to notice: **every break has been in the runtime/framework
layer, none in the wire layer.** OpenFlow 1.3 and the ethernet/IP packet
formats have been frozen since 2012 and upstream does not touch them.

Measured surface
----------------

139 ``os_ken`` references across 30 files: 17 modules under ``faucet/``,
3 under ``clib/``, 2 under ``ofctl_rest/``, 8 under ``tests/``. Faucet
uses 195 distinct ``ofproto_v1_3`` constants and ~50 ``ofproto_v1_3_parser``
classes.

The OF1.3-only import closure of everything faucet touches is 57 modules
and 24,426 lines, which splits cleanly by churn risk:

==========================  =====  ===============================  =========  =========
Layer                       LOC    os-ken modules                   Churns?    Replace
==========================  =====  ===============================  =========  =========
OF1.3 wire protocol         8,503  ``ofproto_v1_3``,                no         ~7,000
                                   ``ofproto_v1_3_parser``,
                                   ``ofproto_parser``,
                                   ``oxm_fields``, ``ether``,
                                   ``inet``, ``ofproto_common``
Packet library              5,944  ``lib/packet/*`` (13 protos),    no         ~4,700
                                   ``addrconv``, ``mac``,
                                   ``stringify``, ``type_desc``
Nicira extensions           5,168  ``nx_actions``, ``nx_match``,    no         ~350
                                   ``nicira_ext``
ofctl helpers               1,656  ``ofctl_v1_3``, ``ofctl_utils``  no         ~200 +
                                                                               ~700 test
App framework               1,562  ``app_manager``, ``handler``,    **yes**    ~400
                                   ``event``, ``ofp_event``,
                                   ``dpset``, ``ofp_handler``
hub / cfg / log             1,037  ``lib/hub``, ``cfg``,            **yes**    ~200
                                   ``flags``, ``log``, ``utils``
OF channel                    556  ``controller/controller``        **yes**    ~350
==========================  =====  ===============================  =========  =========

3,155 lines of that closure -- 13% -- account for 100% of the historical
breakage.

Proposal
--------

A top-level ``c65of`` package alongside ``faucet/`` and ``clib/``, shipped
in the same distribution. Top-level, not under ``faucet/``, because
``tests/run_unit_tests.sh`` runs ``coverage --source faucet/`` at
``--fail-under=91``; ported wire-format code has no business competing
with faucet's own coverage budget.

Module layout mirrors the os-ken paths it replaces, so each call site
changes by exactly one import line::

    c65of/ofproto/__init__.py   OF1.3 constants          (ofproto_v1_3)
    c65of/ofproto/parser.py     OF1.3 messages           (ofproto_v1_3_parser)
    c65of/ofproto/base.py       MsgBase, StringifyMixin, ofp_msg_from_jsondict
    c65of/ofproto/nx.py         NXActionCT/NAT/CTClear + ct_* OXM
    c65of/ofproto/ether.py      ether, inet
    c65of/packet/               11 protocols + packet, stream_parser
    c65of/lib/                  addrconv, mac, stringify, type_desc
    c65of/ofctl.py              to_match_*, OFCtlUtil, mod_meter_entry
    c65of/app.py                OFApp base, set_ev_cls, event dispatch
    c65of/channel.py            OF listener, Datapath, dpset

Both projects are Apache-2.0, so the frozen-format layers are a
license-clean verbatim port with copyright headers and NOTICE preserved --
the same move already made for ``ofctl_rest/wsgi.py``.

Sequencing
----------

The point of the phasing is that phase 0 decouples *changing 30 call
sites* from *reimplementing 24k lines*, and gives every later phase a
differential oracle.

**Phase 0 -- shim, no behaviour change.** Land ``c65of`` as pure
re-exports of os-ken (``from os_ken.ofproto.ofproto_v1_3 import *``).
Repoint all 30 files at ``c65of``. Add a codecheck rule banning direct
``os_ken`` imports outside ``c65of``. Mechanical; green on day one.

**Phase 0b -- differential harness.** Extend the existing packet fuzzer
(``tests/generative/fuzzer/packet/``, ``Dockerfile.fuzz-packet``) to drive
both stacks and assert byte-identical ``serialize()`` and equal
``to_jsondict()``. Every subsequent phase ships with its swap under this
harness rather than under hand-written expectations. Without this the
wire phases are guesswork; with it they are verifiable.

**Phase 1 -- hub, config, app framework** (3,155 os-ken lines to ~600).
Delete ``lib/hub`` in favour of ``threading``/``queue`` used directly --
faucet already runs threads-only and guards it in
``tests/unit/faucet/test_no_eventlet.py``, and the ``HubThread`` daemon
monkeypatch in ``faucet/valve_ryuapp.py`` goes away. Fold ``cfg``/``flags``
into the argparse already in ``faucet/__main__.py``, deleting the inlined
``osken-manager``. Replace ``app_manager``'s multi-app pub/sub with a
single-app dispatcher: faucet is one app plus ``dpset``, and needs none of
the ``_CONTEXTS`` / service-brick / ``send_request`` generality.
Drops oslo.config and eventlet from the dependency tree.

**Phase 2 -- OF channel and dpset** (903 to ~400). Port
``controller/controller.py`` threading-only, dropping the eventlet branch
and the ``send_q``/semaphore machinery that block-on-barrier already
supersedes. Fold ``ofp_handler`` (handshake) and ``dpset`` (datapath
registry) in.

After phase 2 the bleeding has stopped. Phases 3-5 are frozen formats and
can be pinned on os-ken indefinitely if the volume is not worth it.

**Phase 3 -- OF1.3 wire + Nicira** (13,671 to ~7,400). Verbatim port of
the OF1.3 parser; trim Nicira to the three actions faucet uses
(``NXActionCT``, ``NXActionNAT``, ``NXActionCTClear``) and the ``ct_*``
OXM fields, discarding ~4,800 lines of unused extensions. Guarded by
phase 0b.

**Phase 4 -- packet library** (5,944 to ~4,700). Verbatim port of the 11
protocols ``faucet/valve_packet.py`` and ``faucet/valve_route.py`` use.
Deliberately *not* a swap to dpkt or scapy: ``valve_packet.py`` is 939
lines written against the os-ken API, scapy is too slow for the packet-in
path, and dpkt has no LLDP, BPDU or LACP -- either would turn a mechanical
port into a rewrite of faucet's own packet handling.

**Phase 5 -- ofctl helpers** (1,656 to ~200 runtime). ``faucet/valve_of.py``
needs six conversion functions plus ``OFCtlUtil.ofp_port_from_user`` and
``mod_meter_entry``. The rest of ``ofctl_v1_3`` exists only for the
vendored, test-only ``ofctl_rest/``, and can stay a fatter test-scoped
copy next to ``ofctl_rest/wsgi.py``.

**Phase 6 -- removal.** Drop ``os_ken`` from ``requirements.txt``,
``debian/control``, and the ``site-packages/os_ken`` pruning in
``docker/install-faucet.sh``.

Open questions
--------------

* **Stop at phase 2?** ~600 new lines removes oslo.config and eventlet and
  ends the class of breakage we have actually suffered, while os-ken stays
  pinned for the 21k frozen lines. Phases 3-5 buy independence from a
  dependency that has never broken those layers, at ~12k lines to own.
  Recommend landing 0-2 first and deciding on 3-5 with that experience in
  hand.
* **Package name and distribution.** ``c65of`` as a subpackage of the
  ``c65faucet`` wheel, or its own PyPI project so ``ofctl_rest`` and other
  consumers can depend on it directly?
* **Coverage policy for ported code.** Ported wire-format modules sit
  outside ``--source faucet/`` by design; they still want their own gate,
  most naturally the phase 0b differential fuzzer rather than a line
  target.
