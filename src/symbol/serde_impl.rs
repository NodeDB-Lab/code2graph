// SPDX-License-Identifier: Apache-2.0

//! Custom serde implementations for [`SymbolId`].
//!
//! [`SymbolId`] is serialized as its SCIP string (the output of
//! [`SymbolId::to_scip_string`]) and deserialized by parsing that string back
//! via [`SymbolId::from_scip_string`]. This keeps the wire format stable,
//! human-readable, and consistent with the SCIP identity contract: two symbol
//! strings are equal iff they name the same symbol.

use super::id::SymbolId;

impl serde::Serialize for SymbolId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_scip_string())
    }
}

impl<'de> serde::Deserialize<'de> for SymbolId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        SymbolId::from_scip_string(&s).map_err(serde::de::Error::custom)
    }
}
