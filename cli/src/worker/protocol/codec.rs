// SPDX-License-Identifier: Apache-2.0

//! MessagePack encoding and decoding for protocol DTOs.

use super::*;
use zerompk::{Error as MessagePackError, FromMessagePack, Read, ToMessagePack, Write};

fn read_string_capped<'a, R: Read<'a>>(reader: &mut R) -> zerompk::Result<String> {
    let value = reader.read_string()?;
    if value.len() > MAX_STRING_BYTES {
        return Err(MessagePackError::ArrayLengthMismatch {
            expected: MAX_STRING_BYTES,
            actual: value.len(),
        });
    }
    Ok(value.into_owned())
}

macro_rules! impl_numeric_map_codec {
    ($type:ty { required { $($required_key:literal => $required_field:ident : $required_type:ty),* $(,)? } optional { $($optional_key:literal => $optional_field:ident : $optional_type:ty),* $(,)? } }) => {
        impl ToMessagePack for $type {
            fn write<W: Write>(&self, writer: &mut W) -> zerompk::Result<()> {
                writer.write_map_len(0 $(+ { let _ = &$required_key; 1 })* $(+ { let _ = &$optional_key; 1 })*)?;
                $(writer.write_u8($required_key)?; <$required_type as ToMessagePack>::write(&self.$required_field, writer)?;)*
                $(writer.write_u8($optional_key)?; <$optional_type as ToMessagePack>::write(&self.$optional_field, writer)?;)*
                Ok(())
            }
        }
        impl<'a> FromMessagePack<'a> for $type {
            fn read<R: Read<'a>>(reader: &mut R) -> zerompk::Result<Self> {
                reader.increment_depth()?;
                let result = (|| {
                    let len = reader.read_map_len()?;
                    if len > MAX_COLLECTION_ITEMS { return Err(MessagePackError::MapLengthMismatch { expected: MAX_COLLECTION_ITEMS, actual: len }); }
                    $(let mut $required_field: Option<$required_type> = None;)*
                    $(let mut $optional_field: Option<$optional_type> = None;)*
                    for _ in 0..len {
                        match reader.read_u64()? {
                            $($required_key => { if $required_field.is_some() { return Err(MessagePackError::KeyDuplicated(stringify!($required_field).into())); } $required_field = Some(<$required_type as FromMessagePack<'a>>::read(reader)?); })*
                            $($optional_key => { if $optional_field.is_some() { return Err(MessagePackError::KeyDuplicated(stringify!($optional_field).into())); } $optional_field = Some(<$optional_type as FromMessagePack<'a>>::read(reader)?); })*
                            _ => reader.skip_value()?,
                        }
                    }
                    Ok(Self { $($required_field: $required_field.ok_or_else(|| MessagePackError::KeyNotFound(stringify!($required_field).into()))?,)* $($optional_field: $optional_field.unwrap_or_default(),)* })
                })();
                reader.decrement_depth();
                result
            }
        }
    };
}

impl_numeric_map_codec!(QueryBindingRuleWire {
    required { 0 => lang: String, 1 => construct: String, 2 => sql_arg: u64 }
    optional {}
});
impl ToMessagePack for WorkerRequest {
    fn write<W: Write>(&self, writer: &mut W) -> zerompk::Result<()> {
        writer.write_map_len(7)?;
        writer.write_u8(0)?;
        self.version.write(writer)?;
        writer.write_u8(1)?;
        self.kind.write(writer)?;
        writer.write_u8(2)?;
        self.request_id.write(writer)?;
        writer.write_u8(3)?;
        self.path.write(writer)?;
        writer.write_u8(4)?;
        self.language.write(writer)?;
        writer.write_u8(5)?;
        writer.write_binary(&self.source)?;
        writer.write_u8(6)?;
        self.custom_rules.write(writer)?;
        Ok(())
    }
}

impl<'a> FromMessagePack<'a> for WorkerRequest {
    fn read<R: Read<'a>>(reader: &mut R) -> zerompk::Result<Self> {
        reader.increment_depth()?;
        let result = (|| {
            let len = reader.read_map_len()?;
            if len > MAX_COLLECTION_ITEMS {
                return Err(MessagePackError::MapLengthMismatch {
                    expected: MAX_COLLECTION_ITEMS,
                    actual: len,
                });
            }
            let mut version = None;
            let mut kind = None;
            let mut request_id = None;
            let mut path = None;
            let mut language = None;
            let mut source = None;
            let mut custom_rules = None;
            for _ in 0..len {
                match reader.read_u64()? {
                    0 if version.is_none() => version = Some(reader.read_u16()?),
                    1 if kind.is_none() => kind = Some(reader.read_u8()?),
                    2 if request_id.is_none() => request_id = Some(reader.read_u64()?),
                    3 if path.is_none() => path = Some(read_string_capped(reader)?),
                    4 if language.is_none() => language = Some(reader.read_u16()?),
                    5 if source.is_none() => source = Some(reader.read_binary()?.into_owned()),
                    6 if custom_rules.is_none() => {
                        custom_rules = Some(Vec::<QueryBindingRuleWire>::read(reader)?)
                    }
                    0 => return Err(MessagePackError::KeyDuplicated("version".into())),
                    1 => return Err(MessagePackError::KeyDuplicated("kind".into())),
                    2 => return Err(MessagePackError::KeyDuplicated("request_id".into())),
                    3 => return Err(MessagePackError::KeyDuplicated("path".into())),
                    4 => return Err(MessagePackError::KeyDuplicated("language".into())),
                    5 => return Err(MessagePackError::KeyDuplicated("source".into())),
                    6 => return Err(MessagePackError::KeyDuplicated("custom_rules".into())),
                    _ => reader.skip_value()?,
                }
            }
            let source = source.ok_or_else(|| MessagePackError::KeyNotFound("source".into()))?;
            if source.len() > REQUEST_FRAME_MAX {
                return Err(MessagePackError::ArrayLengthMismatch {
                    expected: REQUEST_FRAME_MAX,
                    actual: source.len(),
                });
            }
            Ok(Self {
                version: version.ok_or_else(|| MessagePackError::KeyNotFound("version".into()))?,
                kind: kind.ok_or_else(|| MessagePackError::KeyNotFound("kind".into()))?,
                request_id: request_id
                    .ok_or_else(|| MessagePackError::KeyNotFound("request_id".into()))?,
                path: path.ok_or_else(|| MessagePackError::KeyNotFound("path".into()))?,
                language: language
                    .ok_or_else(|| MessagePackError::KeyNotFound("language".into()))?,
                source,
                custom_rules: custom_rules.unwrap_or_default(),
            })
        })();
        reader.decrement_depth();
        result
    }
}
impl_numeric_map_codec!(WorkerResponse {
    required { 0 => version: u16, 1 => kind: u8, 2 => request_id: RequestId }
    optional { 3 => facts: Option<FileFactsWire>, 4 => error: Option<WorkerErrorWire> }
});
impl_numeric_map_codec!(WorkerErrorWire {
    required { 0 => code: u16, 1 => message: String }
    optional {}
});
impl_numeric_map_codec!(FileFactsWire {
    required { 0 => file: String, 1 => lang: String, 2 => symbols: Vec<SymbolWire>, 3 => references: Vec<ReferenceWire>, 4 => scopes: Vec<ScopeWire>, 5 => bindings: Vec<BindingWire>, 6 => ffi_exports: Vec<FfiExportWire> }
    optional {}
});
impl_numeric_map_codec!(SymbolIdWireDto {
    required { 0 => version: u32, 1 => scip: String }
    optional { 2 => lang: Option<String>, 3 => file: Option<String> }
});
impl_numeric_map_codec!(SymbolWire {
    required { 0 => id: SymbolIdWireDto, 1 => name: String, 2 => kind: u8, 3 => visibility: u8, 4 => entry_points: Vec<EntryPointWire>, 5 => file: String, 6 => line: u32, 7 => span_start: u64, 8 => span_end: u64, 9 => signature: String }
    optional {}
});
impl_numeric_map_codec!(EntryPointWire {
    required { 0 => tag: u8 }
    optional { 1 => value: Option<String> }
});
impl_numeric_map_codec!(OccurrenceWire {
    required { 0 => file: String, 1 => line: u32, 2 => col: u32, 3 => byte: u64 }
    optional {}
});
impl_numeric_map_codec!(ReferenceWire {
    required { 0 => name: String, 1 => occ: OccurrenceWire, 2 => role: u8 }
    optional { 3 => source_module: Option<String>, 4 => from_path: Option<String>, 5 => qualifier: Option<String>, 6 => scope: Option<u64>, 7 => type_ref_ctx: Option<u8>, 8 => is_reexport: Option<bool>, 9 => imported_name: Option<String>, 10 => cross_artifact: Option<bool>, 11 => self_receiver: Option<bool> }
});
impl ToMessagePack for ScopeWire {
    fn write<W: Write>(&self, writer: &mut W) -> zerompk::Result<()> {
        writer.write_map_len(4)?;
        writer.write_u8(0)?;
        self.parent.write(writer)?;
        writer.write_u8(1)?;
        self.start.write(writer)?;
        writer.write_u8(2)?;
        self.end.write(writer)?;
        writer.write_u8(3)?;
        self.kind.write(writer)?;
        Ok(())
    }
}

impl<'a> FromMessagePack<'a> for ScopeWire {
    fn read<R: Read<'a>>(reader: &mut R) -> zerompk::Result<Self> {
        reader.increment_depth()?;
        let result = (|| {
            let len = reader.read_map_len()?;
            if len > MAX_COLLECTION_ITEMS {
                return Err(MessagePackError::MapLengthMismatch {
                    expected: MAX_COLLECTION_ITEMS,
                    actual: len,
                });
            }
            let mut parent = None;
            let mut start = None;
            let mut end = None;
            let mut kind = None;
            for _ in 0..len {
                match reader.read_u64()? {
                    0 if parent.is_none() => parent = Some(Option::<u64>::read(reader)?),
                    1 if start.is_none() => start = Some(reader.read_u64()?),
                    2 if end.is_none() => end = Some(reader.read_u64()?),
                    3 if kind.is_none() => kind = Some(reader.read_u8()?),
                    0 => return Err(MessagePackError::KeyDuplicated("parent".into())),
                    1 => return Err(MessagePackError::KeyDuplicated("start".into())),
                    2 => return Err(MessagePackError::KeyDuplicated("end".into())),
                    3 => return Err(MessagePackError::KeyDuplicated("kind".into())),
                    _ => reader.skip_value()?,
                }
            }
            Ok(Self {
                parent: parent.unwrap_or_default(),
                start: start.ok_or_else(|| MessagePackError::KeyNotFound("start".into()))?,
                end: end.ok_or_else(|| MessagePackError::KeyNotFound("end".into()))?,
                kind: kind.ok_or_else(|| MessagePackError::KeyNotFound("kind".into()))?,
            })
        })();
        reader.decrement_depth();
        result
    }
}
impl_numeric_map_codec!(BindingWire {
    required { 0 => scope: u64, 1 => name: String, 2 => intro: u64, 3 => kind: u8, 4 => target_tag: u8 }
    optional { 5 => target_value: Option<String>, 6 => target_id: Option<SymbolIdWireDto>, 7 => type_name: Option<String> }
});
impl_numeric_map_codec!(FfiExportWire {
    required { 0 => symbol: SymbolIdWireDto, 1 => abi: u8, 2 => export_name: String }
    optional {}
});
