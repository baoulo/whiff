use crate::ExtractError;

/// A bounds-checked little/big-endian cursor over a byte slice. Every read
/// returns [`ExtractError::Truncated`] instead of panicking.
///
/// ```
/// use whiff::io::ByteReader;
/// let mut r = ByteReader::new(b"qoif\x00\x00\x00\x10").skip(4)?;
/// assert_eq!(r.be_u32()?, 16);
/// assert!(r.u8().is_err());
/// # Ok::<(), whiff::ExtractError>(())
/// ```
#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

macro_rules! read_int {
    ($($name:ident, $ty:ty, $from:ident;)*) => {$(
        #[doc = concat!("Read a `", stringify!($ty), "` (`", stringify!($from), "`).")]
        pub fn $name(&mut self) -> Result<$ty, ExtractError> {
            let b = self.array::<{ size_of::<$ty>() }>()?;
            Ok(<$ty>::$from(b))
        }
    )*};
}

impl<'a> ByteReader<'a> {
    /// A cursor at the start of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current offset.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes left after the cursor.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Whether nothing is left.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Skip `n` bytes, consuming the reader (for chaining from `new`).
    pub fn skip(mut self, n: usize) -> Result<Self, ExtractError> {
        self.advance(n)?;
        Ok(self)
    }

    /// Skip `n` bytes.
    pub fn advance(&mut self, n: usize) -> Result<(), ExtractError> {
        self.bytes(n).map(|_| ())
    }

    /// Move to an absolute offset (must be within the data).
    pub fn seek(&mut self, offset: usize) -> Result<(), ExtractError> {
        if offset > self.data.len() {
            return Err(self.truncated(offset - self.pos));
        }
        self.pos = offset;
        Ok(())
    }

    /// Next `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], ExtractError> {
        if n > self.remaining() {
            return Err(self.truncated(n));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Next `N` bytes as an array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], ExtractError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.bytes(N)?);
        Ok(out)
    }

    /// Everything after the cursor.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.data[self.pos..];
        self.pos = self.data.len();
        out
    }

    /// Look at the next `n` bytes without consuming them.
    pub fn peek(&self, n: usize) -> Option<&'a [u8]> {
        self.data.get(self.pos..self.pos.checked_add(n)?)
    }

    /// Consume `expected` or fail with [`ExtractError::Malformed`].
    pub fn tag(&mut self, expected: &[u8]) -> Result<(), ExtractError> {
        let got = self.bytes(expected.len())?;
        if got == expected {
            Ok(())
        } else {
            Err(ExtractError::malformed(format!("expected {expected:02x?} at offset {}", self.pos - expected.len())))
        }
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8, ExtractError> {
        Ok(self.bytes(1)?[0])
    }

    read_int! {
        be_u16, u16, from_be_bytes;
        be_u32, u32, from_be_bytes;
        be_u64, u64, from_be_bytes;
        le_u16, u16, from_le_bytes;
        le_u32, u32, from_le_bytes;
        le_u64, u64, from_le_bytes;
        be_i16, i16, from_be_bytes;
        be_i32, i32, from_be_bytes;
        le_i16, i16, from_le_bytes;
        le_i32, i32, from_le_bytes;
    }

    /// A NUL-terminated byte string (the NUL is consumed, not returned).
    pub fn cstr(&mut self) -> Result<&'a [u8], ExtractError> {
        let rest = &self.data[self.pos..];
        let end = rest.iter().position(|&b| b == 0).ok_or_else(|| self.truncated(rest.len() + 1))?;
        self.pos += end + 1;
        Ok(&rest[..end])
    }

    fn truncated(&self, needed: usize) -> ExtractError {
        ExtractError::Truncated { offset: self.pos as u64, needed: needed as u64 }
    }
}
