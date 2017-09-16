//! This module contains common definitions to rfs_client and rfs_server.

use blowfish::Blowfish;
use block_cipher_trait::BlockCipherVarKey;
use std::io::BufReader;
use std::io::Read;

/// BlowfishKey type.
pub type BlowfishKey = Vec<u8>;
/// Challenge type.
pub type Challenge = Vec<u8>;

/// Returns a cipher given a key.
pub fn get_cipher(key: BlowfishKey) -> Blowfish {
    Blowfish::new(key.as_slice())
}

/// Returns a BufReader given a TcpStream.
pub fn get_buf_reader<R: Read>(stream: R) -> BufReader<R> {
    BufReader::new(stream)
}

/// Identity trait. Encapsulate a name and a secret.
pub trait Identity: Clone {
    fn get_secret(self) -> BlowfishKey;
    fn get_name(self) -> String;
}

/// A client identity.
#[derive(Clone)]
pub struct Client {
    pass: BlowfishKey,
    name: String,
}

impl Client {
    pub fn new(n: String, p: BlowfishKey) -> Client {
        Client {name: n, pass: p}
    }
}

impl Identity for Client {
    fn get_name(self) -> String {
        self.name
    }
    fn get_secret(self) -> BlowfishKey {
        self.pass
    }
}

/// A trait for named things.
pub trait Named {
    type Name;
    fn get_name(self) -> Self::Name;
}

