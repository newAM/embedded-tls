use crate::handshake::finished::Finished;
use crate::TlsError;
use core::marker::PhantomData;
use core::mem::size_of;
use digest::core_api::BlockSizeUser;
use digest::generic_array::ArrayLength;
use digest::Reset;
use heapless::Vec;
use hkdf::Hkdf;
use hmac::digest::OutputSizeUser;
use hmac::{Mac, SimpleHmac};
use sha2::digest::generic_array::{
    typenum::{Unsigned, U12},
    GenericArray,
};
use sha2::Digest;

use sha2::Sha256;

#[cfg(feature = "tls_aes_256_gcm_sha384")]
use sha2::Sha384;

type IvLen = U12;

const HKDF_LABEL_LEN_MAX: usize = size_of::<u16>() + 255 + 255;
/// Create a TLS HKDF label.
///
/// # References
///
/// * [RFC 8446 Section 7.1](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
///
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
fn hkdf_label(
    len: u16,
    label: &[u8],
    context: &[u8],
) -> Result<heapless::Vec<u8, HKDF_LABEL_LEN_MAX>, TlsError> {
    let mut hkdf_label: heapless::Vec<u8, HKDF_LABEL_LEN_MAX> = heapless::Vec::new();
    hkdf_label
        .extend_from_slice(&len.to_be_bytes())
        .map_err(|_| TlsError::InternalError)?;

    const LABEL_PREFIX: &[u8] = b"tls13 ";
    let label_len: u8 =
        u8::try_from(label.len() + LABEL_PREFIX.len()).map_err(|_| TlsError::InternalError)?;

    hkdf_label
        .push(label_len)
        .map_err(|_| TlsError::InternalError)?;
    hkdf_label
        .extend_from_slice(LABEL_PREFIX)
        .map_err(|_| TlsError::InternalError)?;
    hkdf_label
        .extend_from_slice(label)
        .map_err(|_| TlsError::InternalError)?;

    let context_len: u8 = u8::try_from(context.len()).map_err(|_| TlsError::InternalError)?;
    hkdf_label
        .push(context_len)
        .map_err(|_| TlsError::InternalError)?;
    hkdf_label
        .extend_from_slice(context)
        .map_err(|_| TlsError::InternalError)?;

    Ok(hkdf_label)
}

/// TLS `HKDF-Expand-Label` function.
///
/// # References
///
/// * [RFC 8446 Section 7.1](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
///
/// ```text
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
/// ```
pub(crate) fn hkdf_expand_label<D, N: ArrayLength<u8>>(
    secret: &Hkdf<D>,
    label: &[u8],
    context: &[u8],
) -> Result<GenericArray<u8, N>, TlsError>
where
    D: Digest,
{
    let label: heapless::Vec<u8, HKDF_LABEL_LEN_MAX> = hkdf_label(N::to_u16(), label, context);
    let mut okm: GenericArray<u8, N> = Default::default();
    secret
        .expand(&label, &mut okm)
        .map_err(|_| TlsError::InternalError)?;
    Ok(okm)
}

/// TLS `Derive-Secret` function.
///
/// # References
///
/// * [RFC 8446 Section 7.1](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)
///
/// ```text
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label,
///                       Transcript-Hash(Messages), Hash.length)
/// ```
pub(crate) fn derive_secret<D>(
    secret: &Hkdf<D>,
    label: &[u8],
    context: &[u8],
) -> GenericArray<u8, <D as OutputSizeUser>::OutputSize>
where
    D: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser,
{
    let label: heapless::Vec<u8, HKDF_LABEL_LEN_MAX> =
        hkdf_label(<D as OutputSizeUser>::OutputSize::to_u16(), label, context);
    let mut okm: GenericArray<u8, _> = Default::default();
    secret.expand(&label, &mut okm).unwrap();
    okm
}

struct CipherSuite<D>
where
    D: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser,
{
    transcript_hash: D,
    hkdf: Hkdf<D, SimpleHmac<D>>,
    client_traffic_secret: Option<Hkdf<D, SimpleHmac<D>>>,
    server_traffic_secret: Option<Hkdf<D, SimpleHmac<D>>>,
}

impl<D> CipherSuite<D>
where
    D: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser,
{
    pub fn hkdf_expand_label<N: ArrayLength<u8>>(
        &self,
        hkdf: &Hkdf<D, SimpleHmac<D>>,
        label: &[u8],
    ) -> Result<GenericArray<u8, N>, TlsError> {
        let mut okm: GenericArray<u8, N> = Default::default();
        //info!("label {:x?}", label);
        hkdf.expand(label, &mut okm)
            .map_err(|_| TlsError::CryptoError)?;
        //info!("expand {:x?}", okm);
        Ok(okm)
    }

    fn server_iv(&self) -> Result<GenericArray<u8, IvLen>, TlsError> {
        hkdf_expand_label(
            self.server_traffic_secret.as_ref().unwrap(),
            &hkdf_label(IvLen::to_u16(), b"iv", &[])?,
            &[],
        )
    }

    fn client_iv(&self) -> Result<GenericArray<u8, IvLen>, TlsError> {
        hkdf_expand_label(
            self.client_traffic_secret.as_ref().unwrap(),
            &hkdf_label(IvLen::to_u16(), b"iv", &[])?,
            &[],
        )
    }

    fn iv_into_nonce(counter: u64, iv: &mut GenericArray<u8, IvLen>) {
        counter
            .to_be_bytes()
            .iter()
            .enumerate()
            .for_each(|(idx, byte)| iv[idx + 4] ^= byte);
    }

    pub(crate) fn server_nonce(
        &self,
        read_counter: u64,
    ) -> Result<GenericArray<u8, IvLen>, TlsError> {
        let mut iv: GenericArray<u8, IvLen> = self.server_iv()?;
        Self::iv_into_nonce(read_counter, &mut iv);
        Ok(iv)
    }

    pub(crate) fn client_nonce(
        &self,
        write_counter: u64,
    ) -> Result<GenericArray<u8, IvLen>, TlsError> {
        let mut iv: GenericArray<u8, IvLen> = self.client_iv()?;
        Self::iv_into_nonce(write_counter, &mut iv);
        Ok(iv)
    }

    pub(crate) fn server_key<N: ArrayLength<u8>>(&self) -> Result<GenericArray<u8, N>, TlsError> {
        hkdf_expand_label(
            self.server_traffic_secret.as_ref().unwrap(),
            &hkdf_label(N::to_u16(), b"key", &[])?,
            &[],
        )
    }

    pub(crate) fn client_key<N: ArrayLength<u8>>(&self) -> Result<GenericArray<u8, N>, TlsError> {
        hkdf_expand_label(
            self.client_traffic_secret.as_ref().unwrap(),
            &hkdf_label(N::to_u16(), b"key", &[])?,
            &[],
        )
    }
}

pub(crate) enum NegotiatedHash {
    Sha256(Sha256),
    #[cfg(feature = "tls_aes_256_gcm_sha384")]
    Sha384(Sha384),
}

impl digest::Update for NegotiatedHash {
    fn update(&mut self, data: &[u8]) {
        match self {
            NegotiatedHash::Sha256(h) => h.update(data),
            NegotiatedHash::Sha384(h) => h.update(data),
        }
    }
}

enum NegotiatedCipherSuite {
    TlsAes128GcmSha256(CipherSuite<Sha256>),
    #[cfg(feature = "tls_aes_256_gcm_sha384")]
    TlsAes256GcmSha384(CipherSuite<Sha384>),
}

impl NegotiatedCipherSuite {
    pub fn digest_output_size(&self) -> u16 {
        match self {
            NegotiatedCipherSuite::TlsAes128GcmSha256(_) => Sha256::OutputSize,
            #[cfg(feature = "tls_aes_256_gcm_sha384")]
            NegotiatedCipherSuite::TlsAes256GcmSha384(_) => Sha384::OutputSize,
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "tls_aes_256_gcm_sha384")] {
        pub(crate) const DIGEST_MAX_OUTPUT_SIZE: usize = 48;
    } else {
        // tls_aes_128_gcm_sha256
        pub(crate) const DIGEST_MAX_OUTPUT_SIZE: usize = 32;
    }
}

pub struct KeySchedule {
    secret: [u8; DIGEST_MAX_OUTPUT_SIZE],
    cipher_suite: Option<NegotiatedCipherSuite>,
    read_counter: u64,
    write_counter: u64,
}

impl KeySchedule {
    pub fn new() -> Self {
        Self {
            secret: [0; DIGEST_MAX_OUTPUT_SIZE],
            cipher_suite: None,
            read_counter: 0,
            write_counter: 0,
        }
    }

    // pub(crate) fn transcript_hash(&mut self) -> &mut D {
    //     self.transcript_hash.as_mut().unwrap()
    // }

    // pub(crate) fn replace_transcript_hash(&mut self, hash: D) {
    //     self.transcript_hash.replace(hash);
    // }

    pub(crate) fn increment_read_counter(&mut self) {
        self.read_counter = self.read_counter.checked_add(1).unwrap()
    }

    pub(crate) fn increment_write_counter(&mut self) {
        self.write_counter = self.write_counter.checked_add(1).unwrap()
    }

    pub(crate) fn reset_write_counter(&mut self) {
        self.write_counter = 0;
    }

    // pub fn client_finished_verify_data(
    //     &self,
    // ) -> Result<Finished<<D as OutputSizeUser>::OutputSize>, TlsError> {
    //     let key: GenericArray<u8, D::OutputSize> = self.hkdf_expand_label(
    //         self.client_traffic_secret.as_ref().unwrap(),
    //         &self.make_hkdf_label(b"finished", &[], D::OutputSize::to_u16())?,
    //     )?;

    //     let mut hmac = SimpleHmac::<D>::new_from_slice(&key).map_err(|_| TlsError::CryptoError)?;
    //     Mac::update(
    //         &mut hmac,
    //         &self
    //             .cipher_suite
    //             .unwrap()
    //             .transcript_hash
    //             .as_ref()
    //             .unwrap()
    //             .clone()
    //             .finalize(),
    //     );
    //     let verify = hmac.finalize().into_bytes();

    //     Ok(Finished { verify, hash: None })
    // }

    // pub fn verify_server_finished(
    //     &self,
    //     finished: &Finished<<D as OutputSizeUser>::OutputSize>,
    // ) -> Result<bool, TlsError> {
    //     //info!("verify server finished: {:x?}", finished.verify);
    //     //self.client_traffic_secret.as_ref().unwrap().expand()
    //     //info!("size ===> {}", D::OutputSize::to_u16());
    //     let key: GenericArray<u8, D::OutputSize> = self.hkdf_expand_label(
    //         self.cipher_suite
    //             .unwrap()
    //             .server_traffic_secret
    //             .as_ref()
    //             .unwrap(),
    //         &self.make_hkdf_label(b"finished", &[], D::OutputSize::to_u16())?,
    //     )?;
    //     // info!("hmac sign key {:x?}", key);
    //     let mut hmac = SimpleHmac::<D>::new_from_slice(&key).unwrap();
    //     Mac::update(&mut hmac, finished.hash.as_ref().unwrap());
    //     //let code = hmac.clone().finalize().into_bytes();
    //     Ok(hmac.verify(&finished.verify).is_ok())
    //     //info!("verified {:?}", verified);
    //     //unimplemented!()
    // }

    // fn zero() -> GenericArray<u8, <D as OutputSizeUser>::OutputSize> {
    //     GenericArray::default()
    // }

    // fn derived(&mut self) -> Result<(), TlsError> {
    //     self.secret = self.derive_secret(b"derived", &D::new().chain_update(&[]).finalize())?;
    //     Ok(())
    // }

    // pub fn initialize_early_secret(&mut self) -> Result<(), TlsError> {
    //     let (secret, hkdf) =
    //         Hkdf::<D, SimpleHmac<D>>::extract(Some(self.secret.as_ref()), Self::zero().as_slice());
    //     self.hkdf.replace(hkdf);
    //     self.secret = secret;
    //     // no right-hand jaunts (yet)
    //     self.derived()
    // }

    // pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) -> Result<(), TlsError> {
    //     let (secret, hkdf) = Hkdf::<D, SimpleHmac<D>>::extract(Some(self.secret.as_ref()), ikm);
    //     self.secret = secret;
    //     self.hkdf.replace(hkdf);
    //     self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic")?;
    //     self.derived()
    // }

    // pub fn initialize_master_secret(&mut self) -> Result<(), TlsError> {
    //     let (secret, hkdf) =
    //         Hkdf::<D, SimpleHmac<D>>::extract(Some(self.secret.as_ref()), Self::zero().as_slice());
    //     self.secret = secret;
    //     self.hkdf.replace(hkdf);

    //     //let context = self.transcript_hash.as_ref().unwrap().clone().finalize();
    //     //info!("Derive keys, hash: {:x?}", context);

    //     self.calculate_traffic_secrets(b"c ap traffic", b"s ap traffic")?;
    //     self.derived()
    // }

    // fn calculate_traffic_secrets(
    //     &mut self,
    //     client_label: &[u8],
    //     server_label: &[u8],
    // ) -> Result<(), TlsError> {
    //     let transcript_hash = self.transcript_hash.as_ref().unwrap().clone().finalize();
    //     let client_secret = self.derive_secret(client_label, &transcript_hash)?;
    //     self.client_traffic_secret
    //         .replace(Hkdf::from_prk(&client_secret).unwrap());
    //     /*info!(
    //         "\n\nTRAFFIC {} secret {:x?}",
    //         core::str::from_utf8(client_label).unwrap(),
    //         client_secret
    //     );*/
    //     let server_secret = self.derive_secret(server_label, &transcript_hash)?;
    //     self.server_traffic_secret
    //         .replace(Hkdf::from_prk(&server_secret).unwrap());
    //     /*info!(
    //         "TRAFFIC {} secret {:x?}\n\n",
    //         core::str::from_utf8(server_label).unwrap(),
    //         server_secret
    //     );*/
    //     self.read_counter = 0;
    //     self.write_counter = 0;
    //     Ok(())
    // }

    // fn make_hkdf_label(
    //     &self,
    //     label: &[u8],
    //     context: &[u8],
    //     len: u16,
    // ) -> Result<Vec<u8, 512>, TlsError> {
    //     //info!("make label {:?} {}", label, len);
    //     let mut hkdf_label = Vec::new();
    //     hkdf_label
    //         .extend_from_slice(&len.to_be_bytes())
    //         .map_err(|_| TlsError::InternalError)?;

    //     let label_len = 6 + label.len() as u8;
    //     hkdf_label
    //         .extend_from_slice(&(label_len as u8).to_be_bytes())
    //         .map_err(|_| TlsError::InternalError)?;
    //     hkdf_label
    //         .extend_from_slice(b"tls13 ")
    //         .map_err(|_| TlsError::InternalError)?;
    //     hkdf_label
    //         .extend_from_slice(label)
    //         .map_err(|_| TlsError::InternalError)?;

    //     let context_len: u8 = u8::try_from(context.len()).map_err(|_| TlsError::InternalError)?;
    //     hkdf_label
    //         .push(context_len)
    //         .map_err(|_| TlsError::InternalError)?;
    //     hkdf_label
    //         .extend_from_slice(context)
    //         .map_err(|_| TlsError::InternalError)?;

    //     Ok(hkdf_label)
    // }
}

impl Default for KeySchedule {
    fn default() -> Self {
        KeySchedule::new()
    }
}
