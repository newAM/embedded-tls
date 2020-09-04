use drogue_tls_sys::{SSL_VERIFY_NONE, SSL_VERIFY_OPTIONAL, SSL_VERIFY_REQUIRED, SSL_VERIFY_UNSET, ssl_config_defaults, ssl_conf_rng, ctr_drbg_random, ssl_conf_dbg, ssl_set_hostname, SSL_MAX_HOST_NAME_LEN};

pub enum Verify {
    None = SSL_VERIFY_NONE as isize,
    Optional = SSL_VERIFY_OPTIONAL as isize,
    Required = SSL_VERIFY_REQUIRED as isize,
    Unset = SSL_VERIFY_UNSET as isize,
}

use drogue_tls_sys::{
    SSL_IS_SERVER,
    SSL_IS_CLIENT,
};

pub enum Endpoint {
    Server = SSL_IS_SERVER as isize,
    Client = SSL_IS_CLIENT as isize,
}

use drogue_tls_sys::{
    SSL_TRANSPORT_STREAM,
    SSL_TRANSPORT_DATAGRAM,
};

pub enum Transport {
    Stream = SSL_TRANSPORT_STREAM as isize,
    Datagram = SSL_TRANSPORT_DATAGRAM as isize,
}

use drogue_tls_sys::{
    SSL_PRESET_DEFAULT,
    SSL_PRESET_SUITEB,
};

pub enum Preset {
    Default = SSL_PRESET_DEFAULT as isize,
    SuiteB = SSL_PRESET_SUITEB as isize,
}

use drogue_tls_sys::{ssl_config, ssl_config_init, ssl_config_free, ssl_conf_authmode};
use drogue_tls_sys::types::{c_int, c_char, c_void, c_uchar};
use crate::rng::ctr_drbg::CtrDrbgContext;

pub struct SslConfig(
    ssl_config
);

impl SslConfig {
    pub(crate) fn inner(&self) -> &ssl_config {
        &self.0
    }

    pub(crate) fn inner_mut(&mut self) -> &mut ssl_config {
        &mut self.0
    }

    pub fn client(transport: Transport, preset: Preset) -> Result<Self, ()> {
        Self::new(Endpoint::Client, transport, preset)
    }

    pub fn server(transport: Transport, preset: Preset) -> Result<Self, ()> {
        Self::new(Endpoint::Server, transport, preset)
    }

    fn new(endpoint: Endpoint, transport: Transport, preset: Preset) -> Result<Self, ()> {
        let mut cfg = ssl_config::default();
        unsafe { ssl_config_init(&mut cfg) };
        let result = unsafe {
            ssl_config_defaults(&mut cfg,
                                endpoint as c_int,
                                transport as c_int,
                                preset as c_int)
        };

        unsafe {
            ssl_conf_dbg(&mut cfg, Some(debug), 0 as _);
        }

        if result == 0 {
            Ok(Self(cfg))
        } else {
            Err(())
        }
    }

    pub fn authmode(&mut self, auth_mode: Verify) -> &mut Self {
        unsafe { ssl_conf_authmode(self.inner_mut(), auth_mode as c_int) };
        self
    }

    pub fn rng(&mut self, rng_ctx: &mut CtrDrbgContext) -> &mut Self {
        unsafe {
            ssl_conf_rng(
                self.inner_mut(),
                Some(ctr_drbg_random),
                rng_ctx.inner_mut() as *mut _,
            );
        }
        self
    }



    pub fn free(mut self) {
        unsafe { ssl_config_free(&mut self.0) };
    }
}

use core::str::{from_utf8, Utf8Error};


unsafe extern "C" fn debug(
    context: *mut c_void,
    level: c_int,
    file_name: *const c_char,
    line: c_int,
    message: *const c_char,
) {
    let file_name = to_str(&file_name);
    let message = to_str(&message);
    log::info!("{}:{}:{} - {}", level, file_name.unwrap(), line, message.unwrap());
}

fn to_str<'a>(str: &'a *const c_char) -> Result<&'a str, Utf8Error> {
    unsafe {
        let len = strlen(*str);
        let str = *str as *const u8;
        let str = core::slice::from_raw_parts(str, len);
        from_utf8(str)
    }
}

#[inline]
unsafe fn strlen(p: *const c_char) -> usize {
    let mut n = 0;
    while *p.offset(n as isize) != 0 {
        n += 1;
    }
    n
}
