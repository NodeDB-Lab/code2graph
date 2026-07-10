// SPDX-License-Identifier: Apache-2.0

//! Custom serde implementations for [`SymbolId`].
//!
//! SCIP deliberately has no language or local-file coordinate. The lossless
//! versioned wire representation carries those coordinates explicitly while
//! retaining a parseable standard SCIP string.

use super::id::SymbolId;

#[derive(serde::Serialize, serde::Deserialize)]
struct SymbolIdWire {
    #[serde(default = "wire_version")]
    version: u8,
    scip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lang: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
}

const fn wire_version() -> u8 {
    1
}

impl serde::Serialize for SymbolId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (lang, file) = self.wire_context();
        SymbolIdWire {
            version: wire_version(),
            scip: self.to_scip_string(),
            lang: lang.map(str::to_owned),
            file: file.map(str::to_owned),
        }
        .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SymbolId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Input {
            Legacy(String),
            Wire(SymbolIdWire),
        }
        match Input::deserialize(deserializer)? {
            Input::Legacy(s) => SymbolId::from_scip_string(&s).map_err(serde::de::Error::custom),
            Input::Wire(w) => {
                if w.version != wire_version() {
                    return Err(serde::de::Error::custom(format!(
                        "unsupported SymbolId wire version {}",
                        w.version
                    )));
                }
                SymbolId::from_wire(&w.scip, w.lang, w.file).map_err(serde::de::Error::custom)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::symbol::{Descriptor, SymbolId};

    #[test]
    fn legacy_scip_string_remains_readable() {
        let id = SymbolId::global("rust", vec![Descriptor::Term("run".into())]);
        let legacy = serde_json::to_string(&id.to_scip_string()).unwrap();
        assert_eq!(
            serde_json::from_str::<SymbolId>(&legacy)
                .unwrap()
                .to_scip_string(),
            id.to_scip_string()
        );
    }

    #[test]
    fn unsupported_wire_version_is_rejected() {
        let error = serde_json::from_str::<SymbolId>(r#"{"version":2,"scip":"codegraph . run."}"#)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported SymbolId wire version")
        );
    }
}
