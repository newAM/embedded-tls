mod not_rng;

use embedded_io::blocking::{Read, Write};
use embedded_tls::blocking::{Aes128GcmSha256, NoVerify, TlsConfig, TlsConnection, TlsContext};
use embedded_tls::TlsError;
use not_rng::NotRng;

pub struct Fuzz<'b> {
    buf: &'b [u8],
    ptr: usize,
}

impl<'b> From<&'b [u8]> for Fuzz<'b> {
    fn from(buf: &'b [u8]) -> Self {
        Self { buf, ptr: 0 }
    }
}

impl<'b> embedded_io::Io for Fuzz<'b> {
    type Error = TlsError;
}

impl<'b> Read for Fuzz<'b> {
    fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Result<usize, Self::Error> {
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
    fn write<'m>(&'m mut self, buf: &'m [u8]) -> Result<usize, Self::Error> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn main() {
    let config = TlsConfig::new().with_server_name("localhost");

    afl::fuzz!(|data: &[u8]| {
        let fuzz: Fuzz = data.into();
        let mut record_buffer: Vec<u8> = vec![0; 32 * 1024];
        let mut tls: TlsConnection<Fuzz, Aes128GcmSha256> =
            TlsConnection::new(fuzz, &mut record_buffer);
        let mut rng = NotRng::default();

        // ignore the result - only looking for internal panics
        let _ = tls.open::<NotRng, NoVerify>(TlsContext::new(&config, &mut rng));
    });
}
