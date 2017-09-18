//! This module contains common definitions to rfs_client and rfs_server.

use blowfish::Blowfish;
use block_cipher_trait::BlockCipherVarKey;
use std::io::BufReader;
use std::io::Read;
use config::Field;

/// BlowfishKey type.
pub type BlowfishKey = Vec<u8>;
/// Challenge type.
pub type Challenge = Vec<u8>;

/// Returns a cipher given a key.
pub fn get_cipher(key: &BlowfishKey) -> Blowfish {
    Blowfish::new(key.as_slice())
}

/// Returns a BufReader given a TcpStream.
pub fn get_buf_reader<R: Read>(stream: R) -> BufReader<R> {
    BufReader::new(stream)
}

/// Identity trait. Encapsulate a name and a secret.
pub trait Identity: Clone + Named<Name = String> + Sized {
    fn get_secret(&self) -> &BlowfishKey;
}

/// A client identity.
#[derive(Clone)]
pub struct Client {
    key: BlowfishKey,
    name: String,
}

impl Client {
    pub fn new(n: String, k: BlowfishKey) -> Client {
        Client { name: n, key: k }
    }
}

impl Named for Client {
    type Name = String;
    fn get_name(&self) -> &String {
        &self.name
    }
}

impl Identity for Client {
    fn get_secret(&self) -> &BlowfishKey {
        &self.key
    }
}

/// A trait for named things.
pub trait Named {
    type Name;
    fn get_name(&self) -> &Self::Name;
}

/// Print a welcome on the `info` log.
pub fn welcome(s: Field) {
    match s {
        Field::Server {
            name,
            key: _,
            address,
            port,
        } => info!("Welcome on server {} at {}", name, address + ":" + &port),
        Field::Client { name, key: _ } => info!("Welcome on client {}", name),
    }
}
