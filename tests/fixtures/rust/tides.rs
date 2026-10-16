//! Tide predictions for the old harbour.
//!
//! Uses a simple harmonic model.

// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

/// A predicted tide.
#[derive(Debug, Clone)]
pub struct Tide {
    pub hour: u8,
    pub height_m: f64,
}

pub enum Kind {
    High,
    Low,
}

pub trait Predict {
    fn predict(&self, day: u32) -> Vec<Tide>;
}

impl fmt::Display for Tide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}h {:.1} m", self.hour, self.height_m) // a "string // not a comment"
    }
}

pub fn table() -> BTreeMap<u8, f64> {
    /* TODO: load from file */
    BTreeMap::new()
}

macro_rules! metres {
    ($x:expr) => {
        $x as f64
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn empty() {
        assert!(super::table().is_empty());
    }
}
