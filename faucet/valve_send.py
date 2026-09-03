"""Barrier-aware send pipeline for OF datapaths.

Faucet's reload path emits batches of OFP messages whose ordering
matters: a FLOW_MOD that meters via OFPIT_METER must not reach the
switch before the OFPMeterMod that installs that meter has committed.
``valve_of.valve_flowreorder`` already interleaves OFPBarrierRequest
markers between the message kinds when ``Valve.USE_BARRIERS`` is true,
but submitting the barrier request alone does not block the controller:
os-ken's ``send_msg`` returns as soon as the bytes hit ``send_q``, and
the os-ken event loop dispatches further work for the same Ryu app on
the same thread.

This module owns one daemon thread per datapath. The Faucet event
handler hands a prepared message list to ``BarrierAwareSender.submit``
and returns immediately, so ``EventOFPBarrierReply`` can be dispatched
while the worker is parked. The worker registers a waiter against the
barrier xid in ``ValvesManager`` *before* sending, then blocks on the
matching reply (with a timeout that drops the channel rather than
hanging the controller).
"""

import queue
import threading
import time

from c65of.ofproto import parser

BARRIER_TIMEOUT = 5.0


def _ends_with_barrier(batch):
    """True iff ``batch`` is non-empty and ends with an OFPBarrierRequest."""
    return bool(batch) and isinstance(batch[-1], parser.OFPBarrierRequest)


class BarrierAwareSender:
    """Per-datapath worker that pushes prepared message batches in order
    and waits for OFPBarrierReply before continuing past each barrier."""

    def __init__(
        self,
        ryu_dp,
        valves_manager,
        logger,
        barrier_timeout=BARRIER_TIMEOUT,
    ):
        self.ryu_dp = ryu_dp
        self.dp_id = ryu_dp.id
        self.valves_manager = valves_manager
        self.logger = logger
        self.barrier_timeout = barrier_timeout
        # Items are either (batch, on_complete) tuples or _stop_sentinel.
        self._queue: "queue.Queue" = queue.Queue()
        self._stop_sentinel = object()
        self._stopped = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="faucet-sender-%016x" % self.dp_id,
            daemon=True,
        )
        self._thread.start()

    def submit(self, ofmsgs, on_complete=None):
        """Enqueue an already-prepared (reordered) ofmsg batch.

        ``on_complete`` (if given) is invoked from the worker thread once
        the batch has fully drained -- including the OFPBarrierReply for
        the final barrier. If the batch as submitted has no trailing
        barrier, the worker appends one before invoking the callback so
        completion truly means the switch has acked the last message.
        The callback is *not* invoked if the channel is torn down
        mid-batch (sender exits and reconnect re-pushes config).
        """
        if self._stopped.is_set():
            return
        if not ofmsgs and on_complete is None:
            return
        self._queue.put((list(ofmsgs), on_complete))

    def stop(self):
        """Signal the worker to drain and exit. Idempotent."""
        if self._stopped.is_set():
            return
        self._stopped.set()
        self._queue.put(self._stop_sentinel)

    def _run(self):
        try:
            while True:
                item = self._queue.get()
                if item is self._stop_sentinel:
                    return
                batch, on_complete = item
                if on_complete is not None and not _ends_with_barrier(batch):
                    batch.append(parser.OFPBarrierRequest(None))
                if not self._send_batch(batch):
                    return
                if on_complete is not None:
                    try:
                        on_complete()
                    except Exception:  # pylint: disable=broad-except
                        self.logger.exception(
                            "on_complete callback for %016x raised",
                            self.dp_id,
                        )
        except Exception:  # pylint: disable=broad-except
            self.logger.exception("sender thread for %016x crashed", self.dp_id)

    def _send_batch(self, batch):
        """Drain one batch in order. Returns False if the channel was
        torn down mid-batch (in which case the worker should exit and
        let reconnect re-push config)."""
        for ofmsg in batch:
            if self._stopped.is_set():
                return False
            if isinstance(ofmsg, parser.OFPBarrierRequest):
                if not self._send_barrier(ofmsg):
                    return False
            else:
                ofmsg.datapath = self.ryu_dp
                self.ryu_dp.send_msg(ofmsg)
        return True

    def _send_barrier(self, ofmsg):
        """Assign an xid, register a waiter, send, and block on the reply."""
        ofmsg.datapath = self.ryu_dp
        # Assign the xid before send_msg so the waiter can register against
        # it. send_msg is otherwise free to assign one inside ``send_q`` --
        # by which point the reply could already be in flight.
        xid = self.ryu_dp.set_xid(ofmsg)
        event = self.valves_manager.register_barrier(self.dp_id, xid)
        sent_at = time.monotonic()
        try:
            self.ryu_dp.send_msg(ofmsg)
            if not event.wait(self.barrier_timeout):
                self.logger.error(
                    "barrier xid=%u on dp %016x timed out after %.1fs;"
                    " dropping channel",
                    xid,
                    self.dp_id,
                    self.barrier_timeout,
                )
                self.ryu_dp.close()
                return False
            self.logger.debug(
                "barrier xid=%u on dp %016x acked in %.3fs",
                xid,
                self.dp_id,
                time.monotonic() - sent_at,
            )
            return True
        finally:
            # complete_barrier removes on hit; on miss/cancel we still
            # want the dict cleared so the dp_id entry doesn't grow.
            self.valves_manager.discard_barrier(self.dp_id, xid)
