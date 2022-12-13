mod not_rng;

use embedded_tls::blocking::{Aes128GcmSha256, NoVerify, TlsConfig, TlsConnection, TlsContext};
use embedded_tls::TlsError;
use not_rng::NotRng;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

struct LoggedStream {
    stream: TcpStream,
    corpus: File,
}

impl embedded_io::Io for LoggedStream {
    type Error = TlsError;
}

impl embedded_io::blocking::Read for LoggedStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let len = Read::read(&mut self.stream, buf).unwrap();
        self.corpus.write_all(&buf[..len]).unwrap();
        Ok(len)
    }
}

impl embedded_io::blocking::Write for LoggedStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let len = Write::write(&mut self.stream, buf).unwrap();
        Ok(len)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.stream.flush().unwrap();
        Ok(())
    }
}

fn main() {
    let config = TlsConfig::new().with_server_name("localhost");

    let corpus: File = File::create("corpus").unwrap();
    let stream = TcpStream::connect("127.0.0.1:12345").expect("error connecting to server");

    let logged_stream = LoggedStream { stream, corpus };

    let mut record_buffer: Vec<u8> = vec![0; 32 * 1024];
    let mut tls: TlsConnection<LoggedStream, Aes128GcmSha256> =
        TlsConnection::new(logged_stream, &mut record_buffer);
    let mut rng = NotRng::default();

    tls.open::<NotRng, NoVerify>(TlsContext::new(&config, &mut rng))
        .unwrap();
}
