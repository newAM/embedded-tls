#[derive(Default)]
pub struct NotRng {
    val: u8,
}

impl NotRng {
    #[inline]
    fn next_byte(&mut self) -> u8 {
        self.val = self.val.wrapping_add(1);
        self.val
    }
}

impl rand_core::RngCore for NotRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.next_byte().into()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.next_byte().into()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.iter_mut().for_each(|b| *b = self.next_byte());
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.iter_mut().for_each(|b| *b = self.next_byte());
        Ok(())
    }
}

impl rand_core::CryptoRng for NotRng {}
