use base64;
use block_cipher_trait::BlockCipher;
use blowfish::Blowfish;
use generic_array::GenericArray;
use rfs_common::*;
use config::{RfsConfig, Config, RfsConfigError};
use config::Field;
use std::io::BufRead;
use std::io::Result as IoResult;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;


pub struct RfsServer {
    name: String,
    config: RfsConfig,
    listener: TcpListener,
}

pub trait Server {
    fn listen(&self);
}

impl Server for RfsServer {
    fn listen(&self) {
        loop {
            info!("Waiting for a client, press ^C to abort");
            match self.listener.accept() {
                Ok((socket, addr)) => {
                    info!("new tcp client: {:?}", addr);
                    self.handle_client(socket);
                    info!("Connection closed");
                }
                Err(e) => warn!("error: {:?}", e),
            }
        }
    }
}

impl RfsServer {
    pub fn new(name: String, config: RfsConfig) -> Option<Self> {
        let my_conf = config.get_from_name(name);
        match my_conf {
            Ok(&Field::Server {
                   ref name,
                   key: _,
                   ref address,
                   ref port,
               }) => {
                welcome(my_conf.unwrap().clone());
                let socket = address.clone() + ":" + &port;
                match TcpListener::bind(socket) {
                    Ok(l) => Some(RfsServer {
                        name: name.clone(),
                        config: config.clone(),
                        listener: l,
                    }),
                    Err(e) => {
                        error!("Can not create RfsServer. Reason: {}", e);
                        None
                    }
                }
            }
            Ok(&Field::Client { ref name, key: _ }) => {
                error!("Item {} is a client", name);
                None
            }
            Err(e) => {
                error!("Can not create RfsServer. Reason: {}", e);
                None
            }
        }
    }

    fn handle_client(&self, stream: TcpStream) {
        match self.auth_client::<Client>(stream) {
            Some((client, _)) => {
                info!("Client {} authenticated.", client.get_name());
            }
            None => {
                warn!("Authentication failure");
            }

        }
    }

    fn auth_client<I>(&self, mut stream: TcpStream) -> Option<(Client, Blowfish)> {
        let mut reader = get_buf_reader(stream.try_clone().unwrap());
        let challenge = generate_challenge();
        let mut reader_buffer = String::new();

        match self.send_id_request(stream.try_clone().unwrap(), challenge.clone()) {
            Ok(_) => {
                match reader.read_line(&mut reader_buffer) {
                    Ok(n) => info!("Read {} bytes as identity line", n),
                    Err(e) => warn!("Could not read identity: {}", e),
                }
                match self.get_identity(remove_newline(reader_buffer.clone())) {
                    Some(client_identity_pretended) => {
                        info!(
                            "Identity pretended: {}",
                            client_identity_pretended.clone().get_name()
                        );

                        let (client_bf, challenge_response_exp) =
                            client_expected_challenge_response(
                                client_identity_pretended.clone(),
                                challenge,
                            );
                        info!("Challenge expected: {:?}", challenge_response_exp.clone());

                        reader_buffer.clear();
                        match reader.read_line(&mut reader_buffer) {
                            Ok(n) => info!("Read {} bytes as challenge response line", n),
                            Err(e) => warn!("Could not read challenge response: {}", e),
                        }
                        let challenge_response_buf: Challenge = base64::decode(&remove_newline(
                            reader_buffer.clone(),
                        )).unwrap_or_else(|e| {
                            error!("Can not decode {}: {}", reader_buffer, e);
                            panic!()
                        });
                        info!("Challenge received: {:?}", challenge_response_buf.clone());

                        if challenge_response_buf == challenge_response_exp {
                            info!("Client authenticated");
                            stream.write("Client authenticated\n".as_bytes()).expect(
                                "Error",
                            );
                            Some::<(Client, Blowfish)>((client_identity_pretended, client_bf))
                        } else {
                            info!("Authentication failure. Aborting.");
                            let buf = "Authentication failure. Aborting.\n".to_string();
                            match stream.write(buf.as_bytes()) {
                                Ok(_) => info!("NAUTH sent"),
                                Err(e) => warn!("NAUTH not sent: {}", e),
                            };
                            None
                        }
                    }
                    None => None, 
                }
            }
            Err(e) => {
                warn!("ID_REQ not sent: {}", e);
                None
            }
        }
    }


    fn get_config_key(&self, name: String) -> Result<BlowfishKey, RfsConfigError> {
        match self.config.get_from_name(name) {
            Ok(f) => Ok(f.clone().get_secret()),
            Err(e) => Err(e),
        }
    }

    fn send_id_request(&self, mut stream: TcpStream, challenge: Challenge) -> IoResult<usize> {
        info!("Challenge proposed: {:?}", challenge.clone());
        let buf = "Please identify yourself\n".to_string() + &"Challenge is: \"" +
            &base64::encode(&challenge) + &"\"\n";
        stream.write(buf.as_bytes())
    }

    // TODO: Return Option<I> where I: Identity
    fn get_identity(&self, s: String) -> Option<Client> {
        match self.get_config_key(s.clone()) {
            Ok(key) => Some(Client::new(s, key)), 
            Err(e) => {
                warn!("Can not get client identity. Reason: {}", e);
                None
            }
        }
    }
}

fn remove_newline(s: String) -> String {
    let mut my_s = s.clone();
    my_s.pop();
    my_s
}

fn generate_challenge() -> Challenge {
    use rand::os::OsRng;
    use rand::Rng;

    let mut rng = OsRng::new().unwrap();
    let mut buf: [u8; 8] = [0; 8];
    rng.fill_bytes(&mut buf);
    buf.to_vec()
}

fn client_expected_challenge_response<I>(i: I, challenge: Challenge) -> (Blowfish, Challenge)
where
    I: Identity,
{
    let bf = get_cipher(i.get_secret());
    let in_buf = GenericArray::from_slice(&challenge);
    let mut out_buf = GenericArray::new();
    bf.encrypt_block(&in_buf, &mut out_buf);
    (bf, out_buf.to_vec())
}
