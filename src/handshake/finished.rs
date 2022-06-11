use crate::buffer::*;
use crate::parse_buffer::ParseBuffer;
use crate::TlsError;
use core::fmt::{Debug, Formatter};
//use digest::generic_array::{ArrayLength, GenericArray};
use generic_array::{ArrayLength, GenericArray};
use heapless::Vec;
use crate::key_schedule::DIGEST_MAX_OUTPUT_SIZE;

pub struct Finished {
    pub verify: Vec<u8, DIGEST_MAX_OUTPUT_SIZE>,
    pub hash: Option<Vec<u8, DIGEST_MAX_OUTPUT_SIZE>>,
}

#[cfg(feature = "defmt")]
impl defmt::Format for Finished {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "verify length:{}", &self.verify.len());
    }
}

impl Debug for Finished {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Finished")
            .field("verify", &self.hash)
            .finish()
    }
}

impl Finished {
    pub fn parse(buf: &mut ParseBuffer, _len: u32) -> Result<Self, TlsError> {
        // info!("finished len: {}", len);
        let mut verify = GenericArray::default();
        buf.fill(&mut verify)?;
        //let hash = GenericArray::from_slice()
        //let hash: Result<Vec<u8, _>, ()> = buf
        //.slice(len as usize)
        //.map_err(|_| TlsError::InvalidHandshake)?
        //.into();
        // info!("hash {:?}", verify);
        //let hash = hash.map_err(|_| TlsError::InvalidHandshake)?;
        // info!("hash ng {:?}", verify);
        Ok(Self { verify, hash: None })
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        //let len = self.verify.len().to_be_bytes();
        //buf.extend_from_slice(&[len[1], len[2], len[3]]);
        buf.extend_from_slice(&self.verify[..self.verify.len()])
            .map_err(|_| TlsError::EncodeError)?;
        Ok(())
    }
}
