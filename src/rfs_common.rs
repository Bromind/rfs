//! This module contains common definitions to rfs_client and rfs_server.

use blowfish::Blowfish;
use block_cipher_trait::BlockCipherVarKey;
use std::net::TcpStream;
use std::io::BufReader;

/// BlowfishKey type.
pub type BlowfishKey = Vec<u8>;
/// Challenge type.
pub type Challenge = Vec<u8>;

/// Returns a cipher given a key.
pub fn get_cipher(key: BlowfishKey) -> Blowfish {
    Blowfish::new(key.as_slice())
}

/// Returns a BufReader given a TcpStream.
pub fn get_buf_reader(stream: TcpStream) -> BufReader<TcpStream> {
    BufReader::new(stream)
}
