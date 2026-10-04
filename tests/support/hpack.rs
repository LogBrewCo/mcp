//! Encode bounded fixture fields without Huffman coding or ambient table state.

use std::io;

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

// RFC 7541 sections 5.1 and 5.2: a non-Huffman string with a seven-bit length.
fn string(block: &mut Vec<u8>, value: &[u8]) -> TestResult<()> {
    if value.len() > 16 << 10 {
        return Err(io::Error::other("fixture field exceeds byte bound").into());
    }
    if value.len() < 127 {
        block.push(u8::try_from(value.len())?);
    } else {
        block.push(127);
        let mut length = value
            .len()
            .checked_sub(127)
            .ok_or("invalid fixture length")?;
        while length >= 128 {
            block.push(u8::try_from(length & 127)? | 128);
            length >>= 7;
        }
        block.push(u8::try_from(length)?);
    }
    block.extend_from_slice(value);
    Ok(())
}

pub fn literal(block: &mut Vec<u8>, name: &[u8], value: &[u8], indexed: bool) -> TestResult<()> {
    block.push(if indexed { 0x40 } else { 0 });
    string(block, name)?;
    string(block, value)
}
