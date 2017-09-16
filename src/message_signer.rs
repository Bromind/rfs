#![deny(missing_docs)]

//! This module contains all the machinery to sign a message, in order to ensure that it indeed
//! comes from the pretended client (i.e.: to avoid session hijacks).
//!
//! Messages (from `message::Message`) are first serialized, then all bytes are XOR-ed into a
//! checksum. This checksum is then ciphered using the client identity.

use generic_array::GenericArray;
use blowfish::Blowfish;
use std::error::Error;
use message::Message;
use rfs_common::BlowfishKey;
use block_cipher_trait::{BlockCipher, BlockCipherVarKey};
use std::fmt;

#[derive(Debug)]
/// A signed message. Typically built by a `MessageSigner`. It contains a serialized `message::Message` and a checksum.
pub struct SignedMessage {
    serialized_message: Vec<u8>,
    signature: Vec<u8>,
}

/// This trait is implemented by structures which perform the signature of the message.
pub trait MessageSigner {
    /// Given a `message::Message`, returns the signed message, or `None` in case of failure.
    fn sign<M: Message>(&self, message: M) -> Option<SignedMessage>;
    /// Given a `SignedMessage`, assert that the signature is correct with respect to the
    /// content of the serialized message.
    fn assert(&self, message: SignedMessage) -> Result<(), MessageSignerError>;
}

#[derive(Debug)]
enum MessageSignerErrorKind {
    SignatureDontMatch,
}

/// The error type for signing operations.
#[derive(Debug)]
pub struct MessageSignerError {
    kind: MessageSignerErrorKind,
}

impl fmt::Display for MessageSignerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Message Signer Error: {:?}", self.kind)
    }
}

impl Error for MessageSignerError {
    fn description(&self) -> &str {
        match self.kind {
            MessageSignerErrorKind::SignatureDontMatch => "The provided signature and the computed signature don't match",
        }
    }
}

/// A `MessageSigner` which uses the Blowfish encryption method to sign the checksum.
pub struct BlowfishSigner {
    bf: Blowfish,
}

impl BlowfishSigner {
    /// Create a `BlowfishSigner` for the given key.
    pub fn new(bfk: BlowfishKey) -> Self {
        Self {bf: Blowfish::new(bfk.as_slice())}
    }
}

impl MessageSigner for BlowfishSigner {
    fn sign<M: Message>(&self, message: M) -> Option<SignedMessage> {
        match message.serialize() {
            Some(v) => {
                let mut xor: u8 = 0;
                for byte in v.clone() {
                    xor = xor ^ byte;
                    // TODO: Use more than 1 byte
                }
                let in_buf = GenericArray::from_slice(&vec![xor, 0, 0, 0, 0, 0, 0, 0]);
                let mut out_buf = GenericArray::new();
                self.bf.encrypt_block(&in_buf, &mut out_buf);
                Some(SignedMessage {serialized_message: v, signature: out_buf.to_vec()})
            },
            None => None,
        }
    }

    fn assert(&self, message: SignedMessage) -> Result<(), MessageSignerError> {
        let mut xor: u8 = 0;
        for byte in message.serialized_message {
            xor = xor ^ byte;
        }
        let in_buf = GenericArray::from_slice(&vec![xor, 0, 0, 0, 0, 0, 0, 0]);
        let mut out_buf = GenericArray::new();
        self.bf.encrypt_block(&in_buf, &mut out_buf);
        if out_buf.to_vec() == message.signature {
            Ok(())
        } else {
            Err(MessageSignerError {kind: MessageSignerErrorKind::SignatureDontMatch})
        }
    }
}
