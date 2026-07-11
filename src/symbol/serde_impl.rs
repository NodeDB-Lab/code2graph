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

                let parsed =
                    SymbolId::from_scip_string(&w.scip).map_err(serde::de::Error::custom)?;
                SymbolId::from_wire(parsed, w.lang, w.file).map_err(serde::de::Error::custom)
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
    fn versioned_wire_round_trips_global_and_local_identity() {
        let global = SymbolId::global("rust", vec![Descriptor::Term("run".into())]);
        let local = SymbolId::local("src/main.rs", "x0");

        for id in [global, local] {
            let json = serde_json::to_string(&id).unwrap();
            let restored: SymbolId = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, id);
        }
    }

    #[test]
    fn versioned_wire_rejects_invalid_coordinate_combinations() {
        let cases = [
            (
                r#"{"version":1,"scip":"codegraph . . . run."}"#,
                "global SymbolId wire requires lang",
            ),
            (
                r#"{"version":1,"scip":"codegraph . . . run.","file":"src/main.rs"}"#,
                "global SymbolId wire requires lang",
            ),
            (
                r#"{"version":1,"scip":"codegraph . . . run.","lang":"rust","file":"src/main.rs"}"#,
                "global SymbolId wire requires lang",
            ),
            (
                r#"{"version":1,"scip":"local x0"}"#,
                "local SymbolId wire requires file",
            ),
            (
                r#"{"version":1,"scip":"local x0","lang":"rust"}"#,
                "local SymbolId wire requires file",
            ),
            (
                r#"{"version":1,"scip":"local x0","lang":"rust","file":"src/main.rs"}"#,
                "local SymbolId wire requires file",
            ),
        ];

        for (json, expected) in cases {
            let error = serde_json::from_str::<SymbolId>(json).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
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
