// SPDX-License-Identifier: Apache-2.0

//! Length-prefixed frames with a defensive MessagePack structural scan.

use super::protocol::{
    MAX_DEPTH, REQUEST_FRAME_MAX, RESPONSE_FRAME_MAX, WorkerProtocolError, WorkerRequest,
    WorkerResponse,
};
use std::io::{Read as IoRead, Write as IoWrite};

use zerompk::{FromMessagePack, ToMessagePack};

pub fn encode_frame<T: ToMessagePack>(
    value: &T,
    max: usize,
) -> Result<Vec<u8>, WorkerProtocolError> {
    let payload = zerompk::to_msgpack_vec(value).map_err(WorkerProtocolError::Encode)?;
    if payload.is_empty() || payload.len() > max {
        return Err(WorkerProtocolError::FrameTooLarge);
    }
    let len = u32::try_from(payload.len()).map_err(|_| WorkerProtocolError::FrameTooLarge)?;
    let capacity = payload
        .len()
        .checked_add(4)
        .ok_or(WorkerProtocolError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Read one bounded length-prefixed frame. Clean EOF before a prefix is `None`.
pub fn read_frame<R: IoRead>(
    reader: &mut R,
    max: usize,
) -> Result<Option<Vec<u8>>, WorkerProtocolError> {
    let mut prefix = [0_u8; 4];
    match reader.read_exact(&mut prefix[..1]) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(WorkerProtocolError::Io(error)),
    }
    reader
        .read_exact(&mut prefix[1..])
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => {
                WorkerProtocolError::Malformed("truncated length prefix")
            }
            _ => WorkerProtocolError::Io(error),
        })?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 {
        return Err(WorkerProtocolError::Malformed("empty payload"));
    }
    if length > max {
        return Err(WorkerProtocolError::FrameTooLarge);
    }
    let capacity = length
        .checked_add(4)
        .ok_or(WorkerProtocolError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&prefix);
    frame.resize(capacity, 0);
    reader
        .read_exact(&mut frame[4..])
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => WorkerProtocolError::Malformed("truncated frame"),
            _ => WorkerProtocolError::Io(error),
        })?;
    Ok(Some(frame))
}

/// Write one bounded length-prefixed frame.
pub fn write_frame<W: IoWrite, T: ToMessagePack>(
    writer: &mut W,
    value: &T,
    max: usize,
) -> Result<(), WorkerProtocolError> {
    writer.write_all(&encode_frame(value, max)?)?;
    writer.flush()?;
    Ok(())
}

/// Require EOF after one frame, rejecting trailing bytes or a second frame.
pub fn reject_trailing_bytes<R: IoRead>(reader: &mut R) -> Result<(), WorkerProtocolError> {
    let mut byte = [0_u8; 1];
    if reader.read(&mut byte)? == 0 {
        Ok(())
    } else {
        Err(WorkerProtocolError::Malformed(
            "trailing bytes or second frame",
        ))
    }
}

pub fn decode_request_frame(frame: &[u8]) -> Result<WorkerRequest, WorkerProtocolError> {
    decode_frame(frame, REQUEST_FRAME_MAX)
}
pub fn decode_response_frame(frame: &[u8]) -> Result<WorkerResponse, WorkerProtocolError> {
    decode_frame(frame, RESPONSE_FRAME_MAX)
}

fn decode_frame<T: for<'a> FromMessagePack<'a>>(
    frame: &[u8],
    max: usize,
) -> Result<T, WorkerProtocolError> {
    if frame.len() < 4 {
        return Err(WorkerProtocolError::Malformed("missing length prefix"));
    }
    let prefix: [u8; 4] = frame[..4]
        .try_into()
        .map_err(|_| WorkerProtocolError::Malformed("missing length prefix"))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 {
        return Err(WorkerProtocolError::Malformed("empty payload"));
    }
    if length > max {
        return Err(WorkerProtocolError::FrameTooLarge);
    }
    let expected = length
        .checked_add(4)
        .ok_or(WorkerProtocolError::Malformed("length overflow"))?;
    if frame.len() != expected {
        return Err(WorkerProtocolError::Malformed(
            "truncated frame or trailing bytes",
        ));
    }
    let payload = &frame[4..];
    scan_one(payload)?;
    zerompk::from_msgpack(payload).map_err(WorkerProtocolError::Decode)
}

fn scan_one(bytes: &[u8]) -> Result<(), WorkerProtocolError> {
    let mut position = 0;
    scan_value(bytes, &mut position, 0)?;
    if position != bytes.len() {
        return Err(WorkerProtocolError::Malformed("trailing MessagePack value"));
    }
    Ok(())
}
fn take(bytes: &[u8], position: &mut usize, amount: usize) -> Result<(), WorkerProtocolError> {
    let end = position
        .checked_add(amount)
        .ok_or(WorkerProtocolError::Malformed("length overflow"))?;
    if end > bytes.len() {
        return Err(WorkerProtocolError::Malformed(
            "truncated MessagePack value",
        ));
    }
    *position = end;
    Ok(())
}
fn count(bytes: &[u8], p: &mut usize, n: usize) -> Result<usize, WorkerProtocolError> {
    take(bytes, p, n)?;
    let mut value = 0usize;
    for b in &bytes[*p - n..*p] {
        value = value
            .checked_mul(256)
            .and_then(|x| x.checked_add(*b as usize))
            .ok_or(WorkerProtocolError::Malformed("length overflow"))?;
    }
    Ok(value)
}
fn scan_many(
    bytes: &[u8],
    p: &mut usize,
    n: usize,
    depth: usize,
) -> Result<(), WorkerProtocolError> {
    if n > super::protocol::MAX_COLLECTION_ITEMS {
        return Err(WorkerProtocolError::Malformed("collection exceeds limit"));
    }
    for _ in 0..n {
        scan_value(bytes, p, depth)?;
    }
    Ok(())
}

fn scan_map(
    bytes: &[u8],
    p: &mut usize,
    pairs: usize,
    depth: usize,
) -> Result<(), WorkerProtocolError> {
    if pairs > super::protocol::MAX_COLLECTION_ITEMS {
        return Err(WorkerProtocolError::Malformed("collection exceeds limit"));
    }
    let values = pairs
        .checked_mul(2)
        .ok_or(WorkerProtocolError::Malformed("length overflow"))?;
    for _ in 0..values {
        scan_value(bytes, p, depth)?;
    }
    Ok(())
}
fn string(bytes: &[u8], p: &mut usize, n: usize) -> Result<(), WorkerProtocolError> {
    if n > super::protocol::MAX_STRING_BYTES {
        return Err(WorkerProtocolError::Malformed("string value exceeds limit"));
    }
    take(bytes, p, n)
}

fn binary(bytes: &[u8], p: &mut usize, n: usize) -> Result<(), WorkerProtocolError> {
    if n > REQUEST_FRAME_MAX {
        return Err(WorkerProtocolError::Malformed("binary value exceeds limit"));
    }
    take(bytes, p, n)
}

fn extension(bytes: &[u8], p: &mut usize, n: usize) -> Result<(), WorkerProtocolError> {
    if n > super::protocol::MAX_STRING_BYTES {
        return Err(WorkerProtocolError::Malformed(
            "extension value exceeds limit",
        ));
    }
    take(
        bytes,
        p,
        n.checked_add(1)
            .ok_or(WorkerProtocolError::Malformed("length overflow"))?,
    )
}
fn scan_value(bytes: &[u8], p: &mut usize, depth: usize) -> Result<(), WorkerProtocolError> {
    if depth >= MAX_DEPTH {
        return Err(WorkerProtocolError::Malformed(
            "MessagePack nesting exceeds limit",
        ));
    }
    let marker = *bytes.get(*p).ok_or(WorkerProtocolError::Malformed(
        "truncated MessagePack value",
    ))?;
    *p += 1;
    match marker {
        0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => Ok(()),
        0x80..=0x8f => scan_map(bytes, p, (marker & 15) as usize, depth + 1),
        0x90..=0x9f => scan_many(bytes, p, (marker & 15) as usize, depth + 1),
        0xa0..=0xbf => string(bytes, p, (marker & 31) as usize),
        0xc4 => {
            let n = count(bytes, p, 1)?;
            binary(bytes, p, n)
        }
        0xc5 => {
            let n = count(bytes, p, 2)?;
            binary(bytes, p, n)
        }
        0xc6 => {
            let n = count(bytes, p, 4)?;
            binary(bytes, p, n)
        }
        0xc7 => {
            let n = count(bytes, p, 1)?;
            extension(bytes, p, n)
        }
        0xc8 => {
            let n = count(bytes, p, 2)?;
            extension(bytes, p, n)
        }
        0xc9 => {
            let n = count(bytes, p, 4)?;
            extension(bytes, p, n)
        }
        0xca => take(bytes, p, 4),
        0xcb => take(bytes, p, 8),
        0xcc => take(bytes, p, 1),
        0xcd => take(bytes, p, 2),
        0xce => take(bytes, p, 4),
        0xcf => take(bytes, p, 8),
        0xd0 => take(bytes, p, 1),
        0xd1 => take(bytes, p, 2),
        0xd2 => take(bytes, p, 4),
        0xd3 => take(bytes, p, 8),
        0xd4 => take(bytes, p, 2),
        0xd5 => take(bytes, p, 3),
        0xd6 => take(bytes, p, 5),
        0xd7 => take(bytes, p, 9),
        0xd8 => take(bytes, p, 17),
        0xd9 => {
            let n = count(bytes, p, 1)?;
            string(bytes, p, n)
        }
        0xda => {
            let n = count(bytes, p, 2)?;
            string(bytes, p, n)
        }
        0xdb => {
            let n = count(bytes, p, 4)?;
            string(bytes, p, n)
        }
        0xdc => {
            let n = count(bytes, p, 2)?;
            scan_many(bytes, p, n, depth + 1)
        }
        0xdd => {
            let n = count(bytes, p, 4)?;
            scan_many(bytes, p, n, depth + 1)
        }
        0xde => {
            let n = count(bytes, p, 2)?;
            scan_map(bytes, p, n, depth + 1)
        }
        0xdf => {
            let n = count(bytes, p, 4)?;
            scan_map(bytes, p, n, depth + 1)
        }
        0xc1 => Err(WorkerProtocolError::Malformed(
            "reserved MessagePack marker",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scanner_accepts_every_legal_messagepack_marker_class() {
        let values: &[&[u8]] = &[
            &[0x00],
            &[0x7f],
            &[0xe0],
            &[0xff],
            &[0x80],
            &[0x90],
            &[0xa0],
            &[0xc0],
            &[0xc2],
            &[0xc3],
            &[0xc4, 0],
            &[0xc5, 0, 0],
            &[0xc6, 0, 0, 0, 0],
            &[0xc7, 0, 0],
            &[0xc8, 0, 0, 0],
            &[0xc9, 0, 0, 0, 0, 0],
            &[0xca, 0, 0, 0, 0],
            &[0xcb, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xcc, 0],
            &[0xcd, 0, 0],
            &[0xce, 0, 0, 0, 0],
            &[0xcf, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xd0, 0],
            &[0xd1, 0, 0],
            &[0xd2, 0, 0, 0, 0],
            &[0xd3, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xd4, 0, 0],
            &[0xd5, 0, 0, 0],
            &[0xd6, 0, 0, 0, 0, 0],
            &[0xd7, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0xd9, 0],
            &[0xda, 0, 0],
            &[0xdb, 0, 0, 0, 0],
            &[0xdc, 0, 0],
            &[0xdd, 0, 0, 0, 0],
            &[0xde, 0, 0],
            &[0xdf, 0, 0, 0, 0],
        ];
        for value in values {
            assert!(scan_one(value).is_ok(), "marker {:#x}", value[0]);
        }
    }

    #[test]
    fn scanner_rejects_reserved_trailing_truncated_depth_and_oversized_values() {
        assert!(scan_one(&[0xc1]).is_err());
        assert!(scan_one(&[0x01, 0x02]).is_err());
        assert!(scan_one(&[0xd9, 1]).is_err());
        assert!(scan_one(&[0x91; MAX_DEPTH + 1]).is_err());
        assert!(scan_one(&[0xc6, 0x01, 0x00, 0x00, 0x01]).is_err());
        assert!(scan_one(&[0xdb, 0x00, 0x10, 0x00, 0x01]).is_err());
        assert!(scan_one(&[0xc9, 0x00, 0x10, 0x00, 0x01]).is_err());
        assert!(scan_one(&[0xdf, 0x00, 0x0f, 0x42, 0x41]).is_err());
    }

    #[test]
    fn framing_round_trips_and_rejects_length_mismatches() {
        let request = WorkerRequest {
            version: super::super::protocol::PROTOCOL_VERSION,
            kind: 1,
            request_id: 9,
            path: "src/a.rs".into(),
            language: 0,
            source: b"fn run() {}".to_vec(),
        };
        let frame = encode_frame(&request, REQUEST_FRAME_MAX).unwrap();
        let decoded = decode_request_frame(&frame).unwrap();
        assert_eq!(decoded.request_id, request.request_id);
        assert_eq!(decoded.path, request.path);

        let mut truncated = frame.clone();
        truncated.pop();
        assert!(decode_request_frame(&truncated).is_err());

        let mut extra = frame;
        extra.push(0);
        assert!(decode_request_frame(&extra).is_err());
        assert!(decode_request_frame(&[0, 0, 0, 0]).is_err());
        let oversized = u32::try_from(REQUEST_FRAME_MAX + 1).unwrap().to_be_bytes();
        assert!(matches!(
            decode_request_frame(&oversized),
            Err(WorkerProtocolError::FrameTooLarge)
        ));
        assert!(matches!(
            encode_frame(&request, 1),
            Err(WorkerProtocolError::FrameTooLarge)
        ));
    }

    #[test]
    fn streaming_frame_io_distinguishes_eof_truncation_oversize_and_trailing() {
        let request = WorkerRequest {
            version: super::super::protocol::PROTOCOL_VERSION,
            kind: 1,
            request_id: 9,
            path: "src/a.rs".into(),
            language: 0,
            source: b"fn run() {}".to_vec(),
        };
        let mut output = Vec::new();
        write_frame(&mut output, &request, REQUEST_FRAME_MAX).unwrap();
        let mut input = std::io::Cursor::new(output.clone());
        assert!(read_frame(&mut input, REQUEST_FRAME_MAX).unwrap().is_some());
        assert!(reject_trailing_bytes(&mut input).is_ok());

        assert!(
            read_frame(
                &mut std::io::Cursor::new(Vec::<u8>::new()),
                REQUEST_FRAME_MAX
            )
            .unwrap()
            .is_none()
        );
        assert!(read_frame(&mut std::io::Cursor::new(vec![0, 0]), REQUEST_FRAME_MAX).is_err());
        let mut truncated = output.clone();
        truncated.pop();
        assert!(read_frame(&mut std::io::Cursor::new(truncated), REQUEST_FRAME_MAX).is_err());
        let oversized = u32::try_from(REQUEST_FRAME_MAX + 1).unwrap().to_be_bytes();
        assert!(matches!(
            read_frame(&mut std::io::Cursor::new(oversized), REQUEST_FRAME_MAX),
            Err(WorkerProtocolError::FrameTooLarge)
        ));
        output.push(0);
        let mut trailing = std::io::Cursor::new(output);
        assert!(
            read_frame(&mut trailing, REQUEST_FRAME_MAX)
                .unwrap()
                .is_some()
        );
        assert!(reject_trailing_bytes(&mut trailing).is_err());
    }

    #[test]
    fn streaming_read_tolerates_interruption_and_short_reads() {
        struct AdversarialReader {
            bytes: Vec<u8>,
            position: usize,
            interrupt_once: bool,
        }
        impl std::io::Read for AdversarialReader {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if self.interrupt_once {
                    self.interrupt_once = false;
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
                }
                if self.position == self.bytes.len() {
                    return Ok(0);
                }
                let amount = output.len().min(1);
                output[..amount]
                    .copy_from_slice(&self.bytes[self.position..self.position + amount]);
                self.position += amount;
                Ok(amount)
            }
        }

        let frame = encode_frame(
            &WorkerRequest {
                version: super::super::protocol::PROTOCOL_VERSION,
                kind: 1,
                request_id: 9,
                path: "src/a.rs".into(),
                language: 0,
                source: b"fn run() {}".to_vec(),
            },
            REQUEST_FRAME_MAX,
        )
        .unwrap();
        let mut reader = AdversarialReader {
            bytes: frame.clone(),
            position: 0,
            interrupt_once: true,
        };
        assert_eq!(
            read_frame(&mut reader, REQUEST_FRAME_MAX).unwrap(),
            Some(frame)
        );
        assert!(
            read_frame(&mut reader, REQUEST_FRAME_MAX)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn adversarial_frames_return_errors_without_panicking() {
        let corpus: &[&[u8]] = &[
            &[],
            &[0, 0, 0],
            &[0, 0, 0, 1, 0xc1],
            &[0, 0, 0, 2, 0x91, 0x91],
            &[0, 0, 0, 5, 0xdb, 0xff, 0xff, 0xff, 0xff],
            &[0, 0, 0, 5, 0xdf, 0xff, 0xff, 0xff, 0xff],
            &[0, 0, 0, 6, 0xc9, 0xff, 0xff, 0xff, 0xff, 0],
        ];
        for frame in corpus {
            let result = std::panic::catch_unwind(|| decode_request_frame(frame));
            assert!(result.is_ok(), "decoder panicked for {frame:x?}");
            assert!(result.unwrap().is_err(), "decoder accepted {frame:x?}");
        }
    }

    #[test]
    fn decoder_rejects_invalid_utf8_strings_without_panicking() {
        let request = WorkerRequest {
            version: super::super::protocol::PROTOCOL_VERSION,
            kind: 1,
            request_id: 9,
            path: "src/a.rs".into(),
            language: 0,
            source: b"fn run() {}".to_vec(),
        };
        let mut frame = encode_frame(&request, REQUEST_FRAME_MAX).unwrap();
        let start = frame
            .windows(request.path.len())
            .position(|window| window == request.path.as_bytes())
            .expect("encoded path bytes");
        frame[start] = 0xff;
        assert!(decode_request_frame(&frame).is_err());
    }
}
