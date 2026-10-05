//! The trace data model, shared with the UI as generated TypeScript
//! (`cargo test` writes `core/generated/*.ts`).

mod event;
mod evidence;
pub mod invariants;
mod path;
pub mod protocol;
mod trace;

pub use event::*;
pub use evidence::*;
pub use path::*;
pub use protocol::{ProtocolId, TcpIpLayer};
pub use trace::*;
