//! Cancellation and deadlines for Protocol v2 operations (the Go reference's
//! `context.Context`). A context is cheap to clone and safe to share between
//! threads. Cancelling a parent cancels every context derived from it.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Node {
    cancelled: AtomicBool,
    deadline: Option<Instant>,
    parent: Option<Arc<Node>>,
}

impl Node {
    fn done(&self) -> bool {
        if self.cancelled.load(Ordering::SeqCst) {
            return true;
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return true;
        }
        self.parent.as_ref().is_some_and(|p| p.done())
    }
}

/// A cancellation context. [`V2Context::background`] is never done.
#[derive(Clone, Default)]
pub struct V2Context {
    node: Option<Arc<Node>>,
}

/// Cancels the context it was created with (and every context derived from
/// that one). Dropping the handle does not cancel.
#[derive(Clone)]
pub struct V2CancelHandle {
    node: Arc<Node>,
}

impl V2Context {
    /// A context that is never cancelled.
    pub fn background() -> Self {
        V2Context { node: None }
    }

    fn child(&self, deadline: Option<Instant>) -> (V2Context, V2CancelHandle) {
        let node = Arc::new(Node {
            cancelled: AtomicBool::new(false),
            deadline,
            parent: self.node.clone(),
        });
        (
            V2Context {
                node: Some(node.clone()),
            },
            V2CancelHandle { node },
        )
    }

    /// A child context cancelled by the returned handle or by this context.
    pub fn with_cancel(&self) -> (V2Context, V2CancelHandle) {
        self.child(None)
    }

    /// A child context that is also done once `timeout` has elapsed.
    pub fn with_timeout(&self, timeout: Duration) -> (V2Context, V2CancelHandle) {
        self.child(Instant::now().checked_add(timeout))
    }

    /// Whether the context is cancelled or past its deadline.
    pub fn is_done(&self) -> bool {
        self.node.as_ref().is_some_and(|n| n.done())
    }
}

impl V2CancelHandle {
    /// Cancel the context. Idempotent.
    pub fn cancel(&self) {
        self.node.cancelled.store(true, Ordering::SeqCst);
    }
}

impl fmt::Debug for V2Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2Context")
            .field("done", &self.is_done())
            .finish()
    }
}

impl fmt::Debug for V2CancelHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("V2CancelHandle")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_propagates_to_children_only() {
        let root = V2Context::background();
        assert!(!root.is_done());
        let (parent, cancel_parent) = root.with_cancel();
        let (child, cancel_child) = parent.with_cancel();
        cancel_child.cancel();
        assert!(child.is_done());
        assert!(!parent.is_done());
        let (other, _) = parent.with_cancel();
        cancel_parent.cancel();
        assert!(other.is_done());
        assert!(!root.is_done());
    }

    #[test]
    fn timeout_marks_done() {
        let (ctx, _) = V2Context::background().with_timeout(Duration::from_millis(0));
        assert!(ctx.is_done());
    }
}
