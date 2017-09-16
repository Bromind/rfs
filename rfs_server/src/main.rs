use std::net::TcpStream;
use std::net::TcpListener;
use std::io::Write;
use std::io::{BufReader, BufRead};

extern crate rand;

extern crate generic_array;
pub use generic_array::GenericArray;

extern crate base64;

#[macro_use]
extern crate log;
extern crate env_logger;

//extern crate crypto_hashes;
//use crypto_hashes::digest::Digest;

extern crate blowfish;
use blowfish::Blowfish;

extern crate block_cipher_trait;
use block_cipher_trait::{BlockCipher, BlockCipherVarKey};

trait Identity: Clone {
    fn get_secret(self) -> BlowfishKey;
    fn get_name(self) -> String;
}

type BlowfishKey = Vec<u8>;
type Challenge = Vec<u8>;

#[derive(Clone)]
struct Client {
    pass: BlowfishKey,
    name: String,
}

impl Client {
    fn new(n: String, p: BlowfishKey) -> Client {
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

fn main() {
    start_logger();
    match TcpListener::bind("localhost:4242") {
        Ok(listener) => {
            println!("Listener ready...");
            loop{
                println!("Waiting for a client, press ^C to abort");
                match listener.accept() {
                    Ok((socket, addr)) => {
                        info!("new tcp client: {:?}", addr);
                        handle_client(socket);
                        info!("Connection closed");
                    },
                    Err(e) => warn!("error: {:?}", e)
                }
            }
        },
        Err(e) => error!("error: {:?}", e)
    }
}

fn handle_client(mut stream: TcpStream) {
    let message = "My messa";

    let bf = get_cipher(get_config_local_key());
    let mut out_buf = GenericArray::new();
    let in_buf = GenericArray::from_slice(message.as_bytes());
    bf.encrypt_block(&in_buf, &mut out_buf);
    match stream.try_clone() {
        Ok(stream_clone) => 
            match auth_client::<Client>(stream_clone) {
                Some(_) => {
                    let buf = "Message chiffré\n".to_string() 
                        + &base64::encode(&out_buf.to_vec()) 
                        + &"\n";
                    match stream.write(buf.as_bytes()){
                        Ok(_) => info!("Message sent"),
                        Err(e) => warn!("Message not sent: {}", e),
                    }
                },
                None => {
                    warn!("Authentication failure");
                },

            },
        Err(e) => warn!("Can not clone stream: {}", e),
    }
}

fn auth_client<I>(mut stream: TcpStream) -> Option<(Client, Blowfish)> {
    let mut reader = get_buf_reader(stream.try_clone().unwrap());
    let challenge = generate_challenge();
    let mut reader_buffer = String::new();

    match send_id_request(stream.try_clone().unwrap(), challenge.clone()) {
        Ok(_) => 
        {
            match reader.read_line(&mut reader_buffer) {
                Ok(n) => info!("Read {} bytes as identity line", n),
                Err(e) => warn!("Could not read identity: {}", e),
            }
            let client_identity_pretended = get_client_local_identity(remove_newline(reader_buffer.clone()));
            info!("Identity pretended: {}", client_identity_pretended.clone().get_name());

            let (client_bf, challenge_response_exp) = client_expected_challenge_response(client_identity_pretended.clone(), challenge);
            info!("Challenge expected: {:?}", challenge_response_exp.clone());

            reader_buffer.clear();
            match reader.read_line(&mut reader_buffer) {
                Ok(n) => info!("Read {} bytes as challenge response line", n),
                Err(e) => warn!("Could not read challenge response: {}", e),
            }
            let challenge_response_buf: Challenge =
                base64::decode(&remove_newline(reader_buffer.clone()))
                .unwrap_or_else(|e| {error!("Can not decode {}: {}", reader_buffer, e); panic!()});
            info!("Challenge received: {:?}", challenge_response_buf.clone());

            if challenge_response_buf == challenge_response_exp {
                info!("Client authenticated");
                stream.write("Client authenticated\n".as_bytes()).expect("Error");
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
        Err(e) => {
            warn!("ID_REQ not sent: {}", e);
            None
        }
    }
}

fn client_expected_challenge_response<I>(i: I, challenge: Challenge) -> (Blowfish, Challenge) where I: Identity{
    let bf = get_cipher(i.get_secret());
    let in_buf = GenericArray::from_slice(&challenge);
    let mut out_buf = GenericArray::new();
    bf.encrypt_block(&in_buf , &mut out_buf);
    (bf, out_buf.to_vec())
}

fn generate_challenge() -> Challenge {
    use rand::os::OsRng;
    use rand::Rng;

    let mut rng = OsRng::new().unwrap();
    let mut buf: [u8; 8] = [0; 8];
    rng.fill_bytes(&mut buf);
    buf.to_vec()
}

fn send_id_request(mut stream: TcpStream, challenge: Challenge) -> std::io::Result<usize> {
    info!("Challenge proposed: {:?}", challenge.clone());
    let buf = "Please identify yourself\n".to_string()
        + &"Challenge is: \""
        + &base64::encode(&challenge)
        + &"\"\n";
    stream.write(buf.as_bytes()) 
}

fn get_client_local_identity(s: String) -> Client {
    Client::new(s.clone(), get_config_client_key(s))
}

fn remove_newline(s: String) -> String {
    let mut my_s = s.clone();
    my_s.pop();
    my_s
}

fn get_cipher(key: BlowfishKey) -> Blowfish {
    Blowfish::new(key.as_slice())
}

fn start_logger() {
    match env_logger::init() {
         Ok(()) => info!("Logger started"),
         Err(e) => print!("Error during logger initialisation. Reason: {}", e),
    }
}

fn get_buf_reader(stream: TcpStream) -> BufReader<TcpStream> {
    BufReader::new(stream)
}

fn get_config_client_key(client_name: String) -> BlowfishKey {
    vec![3, 0, 0, 0]
}

fn get_config_local_key() -> BlowfishKey {
    vec![2, 0, 0, 0]
}
