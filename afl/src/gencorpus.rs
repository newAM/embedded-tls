mod not_rng;

use embedded_tls::blocking::{Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext};
use embedded_tls::traits::{Read as TlsRead, Write as TlsWrite};
use embedded_tls::{NoClock, TlsError};
use not_rng::NotRng;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

struct LoggedStream {
    stream: TcpStream,
    corpus: File,
}

impl TlsRead for LoggedStream {
    fn read<'m>(&'m mut self, buf: &'m mut [u8]) -> Result<usize, TlsError> {
        let len = Read::read(&mut self.stream, buf).unwrap();
        self.corpus.write_all(&buf[..len]).unwrap();
        Ok(len)
    }
}

impl TlsWrite for LoggedStream {
    fn write<'m>(&'m mut self, buf: &'m [u8]) -> Result<usize, TlsError> {
        let len = Write::write(&mut self.stream, buf).unwrap();
        Ok(len)
    }
}

fn main() {
    let config = TlsConfig::new()
        .with_server_name("localhost")
        .verify_cert(false);

    let corpus: File = File::create("corpus").unwrap();
    let stream = TcpStream::connect("127.0.0.1:12345").expect("error connecting to server");

    let logged_stream = LoggedStream { stream, corpus };

    let mut record_buffer: Vec<u8> = vec![0; 32 * 1024];
    let mut tls: TlsConnection<LoggedStream, Aes128GcmSha256> =
        TlsConnection::new(logged_stream, &mut record_buffer);
    let mut rng = NotRng::default();

    tls.open::<NotRng, NoClock, 4096>(TlsContext::new(&config, &mut rng))
        .unwrap();
}
