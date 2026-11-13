//! Serialising `f32` values so the JSON is always valid.
//!
//! JSON has no NaN or infinity. serde_json would write them as `null`, which
//! then fails to parse back as a number. These helpers clamp instead:
//! NaN becomes 0, +inf becomes `f32::MAX`, -inf becomes `f32::MIN`.
//! Fields use them through `#[serde(serialize_with = "...")]`.

use serde::Serializer;
use serde::ser::SerializeSeq;

/// Maps any `f32` to a finite value that JSON can carry.
pub fn finite(v: f32) -> f32 {
    if v.is_nan() {
        0.0
    } else if v == f32::INFINITY {
        f32::MAX
    } else if v == f32::NEG_INFINITY {
        f32::MIN
    } else {
        v
    }
}

/// Serialises one `f32`, clamped to a finite value.
pub fn ser_f32<S: Serializer>(v: &f32, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f32(finite(*v))
}

/// Serialises a list of `f32`, each clamped to a finite value.
pub fn ser_f32_vec<S: Serializer>(v: &[f32], s: S) -> Result<S::Ok, S::Error> {
    let mut seq = s.serialize_seq(Some(v.len()))?;
    for x in v {
        seq.serialize_element(&finite(*x))?;
    }
    seq.end()
}

/// Serialises an optional `f32`, clamped to a finite value.
pub fn ser_opt_f32<S: Serializer>(v: &Option<f32>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(x) => s.serialize_some(&finite(*x)),
        None => s.serialize_none(),
    }
}
