//! Reading and writing the encodings of RFC 8446 section 3: big-endian
//! integers and length-prefixed vectors. Every read is bounds-checked and
//! returns `None` past the end; nothing here indexes or panics.

/// A cursor over untrusted bytes.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { rest: bytes }
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// What is left, all of it.
    pub fn rest(self) -> &'a [u8] {
        self.rest
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.rest.split_at_checked(n)?;
        self.rest = rest;
        Some(taken)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.bytes(1)?.first().copied()
    }

    pub fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
    }

    pub fn u24(&mut self) -> Option<usize> {
        let b = self.bytes(3)?;
        Some(usize::from(*b.first()?) << 16 | usize::from(*b.get(1)?) << 8 | usize::from(*b.get(2)?))
    }

    /// A vector with a one-byte length, as a reader of its contents.
    pub fn vec8(&mut self) -> Option<Reader<'a>> {
        let n = usize::from(self.u8()?);
        Some(Reader::new(self.bytes(n)?))
    }

    pub fn vec16(&mut self) -> Option<Reader<'a>> {
        let n = usize::from(self.u16()?);
        Some(Reader::new(self.bytes(n)?))
    }

    pub fn vec24(&mut self) -> Option<Reader<'a>> {
        let n = self.u24()?;
        Some(Reader::new(self.bytes(n)?))
    }

    /// The reader holds nothing more; for the end of a structure.
    pub fn end(self) -> Option<()> {
        self.rest.is_empty().then_some(())
    }
}

/// Appends encodings to a byte vector.
#[derive(Default)]
pub struct Writer {
    pub bytes: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer::default()
    }

    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.bytes.push(value);
        self
    }

    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn raw(&mut self, value: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(value);
        self
    }

    /// A vector with a length of `width` bytes (1, 2 or 3) whose contents
    /// `f` writes. Contents too long for the width are a bug in the caller;
    /// they are written with a truncated length, which the peer refuses.
    pub fn vec(&mut self, width: usize, f: impl FnOnce(&mut Writer)) -> &mut Self {
        let at = self.bytes.len();
        self.bytes.extend(std::iter::repeat_n(0, width));
        f(self);
        let length = self.bytes.len().saturating_sub(at).saturating_sub(width);
        let encoded = u32::try_from(length).unwrap_or(u32::MAX).to_be_bytes();
        let size = self.bytes.get_mut(at..at.saturating_add(width)).unwrap_or(&mut []);
        for (to, from) in size.iter_mut().zip(encoded.iter().skip(4usize.saturating_sub(width))) {
            *to = *from;
        }
        self
    }
}

// Proofs, checked by Kani (tools/prove.sh).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// However lengths in the input lie, reading never panics, and every
    /// vector read lies within the input.
    #[kani::proof]
    #[kani::unwind(10)]
    fn vectors_stay_within_the_input() {
        let bytes: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 8);
        let mut r = Reader::new(&bytes[..len]);
        let which: u8 = kani::any();
        let inner = match which % 3 {
            0 => r.vec8(),
            1 => r.vec16(),
            _ => r.vec24(),
        };
        if let Some(inner) = inner {
            assert!(inner.rest().len() + r.rest().len() < len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_never_goes_past_the_end() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03]);
        assert_eq!(r.u16(), Some(0x0102));
        assert_eq!(r.u16(), None);
        assert_eq!(r.u8(), Some(0x03));
        assert_eq!(r.u8(), None);
        assert!(Reader::new(&[0x05, 1, 2]).vec8().is_none());
        assert!(Reader::new(&[0x00, 0x03, 1, 2]).vec16().is_none());
        assert!(Reader::new(&[0x00, 0x00, 0x02, 1]).vec24().is_none());
        let mut r = Reader::new(&[0x00, 0x00, 0x02, 7, 8, 9]);
        assert_eq!(r.vec24().unwrap().rest(), &[7, 8]);
        assert_eq!(r.rest(), &[9]);
    }

    #[test]
    fn vectors_get_their_length() {
        let mut w = Writer::new();
        w.vec(2, |w| {
            w.u8(1).vec(1, |w| {
                w.raw(b"ab");
            });
        })
        .vec(3, |w| {
            w.u16(0xbeef);
        });
        assert_eq!(w.bytes, [0, 4, 1, 2, b'a', b'b', 0, 0, 2, 0xbe, 0xef]);
    }
}
