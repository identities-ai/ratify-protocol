"""Cancellation and deadlines for Protocol v2 calls (Go ``context.Context``).

Every v2 function whose Go counterpart takes a ``context.Context`` takes a
:class:`Context` as its first argument. A context is cancelled explicitly or
by its deadline, and a child is cancelled with its parent. ``err()`` returns
``None`` while the context is live, a :class:`Cancelled` instance after
cancellation, and a :class:`DeadlineExceeded` instance after the deadline.

Deadlines use the monotonic clock. They bound how long the caller waits for a
provider; they never stand in for the authoritative Protocol clock.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

from .errors_v2 import V2Error, V2ErrorClass


class ContextError(V2Error):
    """Base class of the two context termination errors. A cancelled or
    expired operation is ``evaluation_cancelled`` (SPEC-v2 §2.7)."""

    def __init__(self, message: str):
        super().__init__(V2ErrorClass.EVALUATION_CANCELLED, message)


class Cancelled(ContextError):
    """Go ``context.Canceled``: the caller cancelled the context."""

    def __init__(self, message: str = "context canceled"):
        super().__init__(message)


class DeadlineExceeded(ContextError):
    """Go ``context.DeadlineExceeded``: the context deadline passed."""

    def __init__(self, message: str = "context deadline exceeded"):
        super().__init__(message)


class Context:
    """A cancellable context. Create one with :func:`background`,
    :func:`with_cancel`, or :func:`with_timeout`."""

    __slots__ = ("_parent", "_deadline", "_lock", "_event", "_err", "_children")

    def __init__(self, parent: Optional["Context"] = None, deadline: Optional[float] = None):
        self._parent = parent
        self._deadline = deadline
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._err: Optional[ContextError] = None
        self._children: list[Context] = []
        if parent is not None:
            if parent._deadline is not None and (deadline is None or parent._deadline < deadline):
                self._deadline = parent._deadline
            parent._attach(self)

    def _attach(self, child: "Context") -> None:
        with self._lock:
            err = self._err
            if err is None:
                self._children.append(child)
        if err is not None:
            child._finish(err)

    def _finish(self, err: ContextError) -> None:
        with self._lock:
            if self._err is not None:
                return
            self._err = err
            children, self._children = self._children, []
        self._event.set()
        for child in children:
            child._finish(err)

    def cancel(self) -> None:
        """Cancel this context and every context derived from it."""
        self._finish(Cancelled())

    def err(self) -> Optional[ContextError]:
        """``None`` while live; the termination error once done."""
        with self._lock:
            err = self._err
        if err is not None:
            return err
        if self._deadline is not None and time.monotonic() >= self._deadline:
            self._finish(DeadlineExceeded())
            return self.err()
        return None

    def done(self) -> bool:
        return self.err() is not None

    def deadline(self) -> Optional[float]:
        """The monotonic deadline, or ``None``."""
        return self._deadline

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Block until the context is done or ``timeout`` seconds pass.
        Returns whether the context is done."""
        if self.err() is not None:
            return True
        limit = timeout
        if self._deadline is not None:
            remaining = max(0.0, self._deadline - time.monotonic())
            limit = remaining if limit is None else min(limit, remaining)
        self._event.wait(limit)
        return self.err() is not None


_BACKGROUND = Context()


def background() -> Context:
    """A context that is never cancelled (Go ``context.Background``)."""
    return _BACKGROUND


def with_cancel(parent: Context) -> Context:
    """A child of ``parent`` that can be cancelled independently."""
    if not isinstance(parent, Context):
        raise TypeError("parent must be a Context")
    return Context(parent)


def with_timeout(parent: Context, seconds: float) -> Context:
    """A child of ``parent`` that is done after ``seconds`` (monotonic)."""
    if not isinstance(parent, Context):
        raise TypeError("parent must be a Context")
    return Context(parent, time.monotonic() + float(seconds))


def require_context(ctx: object) -> Context:
    """Go ``if ctx == nil``: a v2 call requires a context."""
    if not isinstance(ctx, Context):
        raise TypeError("a ratify_protocol_v2.context_v2.Context is required")
    return ctx
