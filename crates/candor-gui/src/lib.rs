//! Candor desktop client library: the view-model, the data sources and
//! (from WP20) the egui views. `main.rs` is a thin binary around it, and the
//! UI tests use it directly.
#![forbid(unsafe_code)]

pub mod access;
pub mod app;
pub mod ghui;
pub mod map;
pub mod mapview;
pub mod model;
pub mod net;
pub mod settings;
pub mod theme;
pub mod ui;
pub mod widgets;
