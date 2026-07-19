// SPDX-License-Identifier: Apache-2.0

//! Evaluation harness for code2graph: scores ref→def resolution quality
//! (precision / recall / F1) per language and per resolver tier against a corpus
//! of golden fixtures.
//!
//! The harness is a *consumer* of code2graph's public API — it imposes no policy
//! on the library and exists only to turn "best at code→graph" into a measured,
//! improvable number. See [`score`] for the evaluation model and [`corpus`] for
//! the fixture format.

pub mod corpus;
pub mod diagnose;
#[cfg(feature = "oracle-regen")]
pub mod oracle;
pub mod runner;
pub mod score;
