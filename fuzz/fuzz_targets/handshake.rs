#![no_main]
use embedded_tls::{
    blocking::{Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext},
    traits::{Read, Write},
    NoClock, TlsError,
};
use libfuzzer_sys::fuzz_target;

pub struct Fuzz<'b> {
    buf: &'b [u8],
    ptr: usize,
}

impl<'b> From<&'b [u8]> for Fuzz<'b> {
    fn from(buf: &'b [u8]) -> Self {
        Self { buf, ptr: 0 }
    }
}

impl<'b> Read for Fuzz<'b> {
    fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Result<usize, TlsError> {
        let fuzz: &[u8] = self
            .buf
            .get(self.ptr..(self.ptr + buf.len()))
            .ok_or(TlsError::InternalError)?;
        self.ptr += buf.len();
        buf.copy_from_slice(fuzz);
        Ok(buf.len())
    }
}

impl<'b> Write for Fuzz<'b> {
    fn write<'m>(&'m mut self, buf: &'m [u8]) -> Result<usize, TlsError> {
        Ok(buf.len())
    }
}

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

fuzz_target!(|data: &[u8]| {
    let config = TlsConfig::new()
        .with_server_name("localhost")
        .verify_cert(false);

    let fuzz: Fuzz = data.into();
    let mut record_buffer: Vec<u8> = vec![0; 32 * 1024];
    let mut tls: TlsConnection<Fuzz, Aes128GcmSha256> =
        TlsConnection::new(fuzz, &mut record_buffer);
    let mut rng = NotRng::default();

    // ignore the result - only looking for internal panics right now
    let _ = tls.open::<NotRng, NoClock, 4096>(TlsContext::new(&config, &mut rng));
});
