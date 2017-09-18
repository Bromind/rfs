use blowfish::Blowfish;
use config::{RfsConfig, Config, Field};
use block_cipher_trait::BlockCipher;
use std::net::TcpStream;
use std::io::Write;
use std::io::BufRead;
use generic_array::GenericArray;
use std::net::Shutdown;
use base64;
use rfs_common::{Identity, Named, Challenge, BlowfishKey, get_cipher, get_buf_reader};
use std::io::Error as IoError;

pub struct RfsClientSession {
    stream: TcpStream,
    config: RfsConfig,
    identity: Field,
    bf: Blowfish,
}

pub trait Client {
    fn connect(&mut self);
    fn disconnect(&self) -> Result<(), IoError>;
}

impl RfsClientSession {
    pub fn new(serverName: String, clientName: String, config: RfsConfig) -> Option<Self> {
        match config.clone().get_from_name(clientName) {
            Ok(id) => {
                match config.clone().get_server_address(serverName) {
                    Some(address) => {
                        match RfsClientSession::connect_server(address) {
                            Some(stream) => Some(RfsClientSession {
                                stream,
                                config,
                                identity: id.clone(),
                                bf: get_cipher(id.get_secret()),
                            }),
                            None => {
                                warn!("Could not create RfsClientSession (Can not connect).");
                                None
                            }
                        }
                    }
                    None => {
                        warn!("Could not create RfsClientSession.");
                        None
                    }
                }
            }
            Err(e) => {
                warn!("Could not create RfsClientSession. Reason: {}", e);
                None
            }
        }
    }

    fn send_identity(&mut self) {
        let name = self.identity.get_name();
        self.stream.write(name.as_bytes());
        self.stream.write("\n".as_bytes());
    }

    fn connect_server(address: String) -> Option<TcpStream> {
        match TcpStream::connect(address) {
            Ok(stream) => {
                info!("Connection successful");
                Some(stream)
            }
            Err(e) => {
                warn!("Error connecting to server. Reason: {}", e);
                None
            }
        }
    }

    fn authenticate(&mut self) {
        match get_challenge(self.stream.try_clone().unwrap()) {
            Some(c) => {
                info!("Challenge is: {:?}", c);
                self.send_identity();
                let c_resp = get_challenge_response(c, self.bf);
                send_challenge_response(self.stream.try_clone().unwrap(), c_resp);
            }
            None => {
                warn!("Could not get challenge");
            }
        }
    }
}

impl Client for RfsClientSession {
    fn connect(&mut self) {
        self.authenticate()
    }

    fn disconnect(&self) -> Result<(), IoError> {
        info!("Shutdown connection");
        self.stream.shutdown(Shutdown::Both)
    }
}

fn get_challenge(stream: TcpStream) -> Option<Challenge> {
    let mut buf = get_buf_reader(stream);
    let mut challenge_line = String::new();
    buf.read_line(&mut challenge_line);
    let mut challenge_line = String::new();
    buf.read_line(&mut challenge_line);
    let mut challenge_split = challenge_line.split('\"');
    challenge_split.next().unwrap();
    let splitted_line_2 = challenge_split.next().unwrap();
    let challenge = base64::decode(splitted_line_2);
    match challenge {
        Ok(v) => {
            info!("Challenge found: {:?}", v);
            Some(v)
        }
        Err(e) => {
            warn!("Can not decode {}: {}", splitted_line_2, e);
            None
        }
    }

}

fn send_challenge_response(mut stream: TcpStream, c: Challenge) {
    info!("Sending challenge: {:?}", c);
    stream.write(base64::encode(&c).as_bytes());
    stream.write("\n".as_bytes());
}

fn get_challenge_response(c: Challenge, b: Blowfish) -> Challenge {
    let mut out_buf = GenericArray::new();
    let in_buf = GenericArray::from_slice(&c);
    b.encrypt_block(&in_buf, &mut out_buf);
    out_buf.to_vec()
}
