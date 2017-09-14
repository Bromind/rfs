use generic_array::GenericArray;
use blowfish::Blowfish;
use std::error::Error;
use message::Message;
use BlowfishKey;
use block_cipher_trait::{BlockCipher, BlockCipherVarKey};
use std::fmt;

#[derive(Debug)]
    pub struct SignedMessage {
        serialized_message: Vec<u8>,
        signature: Vec<u8>,
    }

    pub trait MessageSigner {
        fn sign<M: Message>(&self, message: M) -> Option<SignedMessage>;
        fn assert(&self, message: SignedMessage) -> Result<(), MessageSignerError>;
    }

#[derive(Debug)]
    enum MessageSignerErrorKind {
        SignatureDontMatch,
    }

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

    pub struct BlowfishSigner {
        bf: Blowfish,
    }

    impl BlowfishSigner {
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
