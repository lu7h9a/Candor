//! Root integration tests for SysScope.
//!
//! The tests in this crate start the real daemon, run the ground-truth
//! workload from `testkit/wl` and compare what the tracer saw with what the
//! workload says it did. They need root and run only through `make test-root`.
#![forbid(unsafe_code)]
