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
    fn get_secret(self) -> String;
    fn get_name(self) -> String;
}

type Challenge = Vec<u8>;

#[derive(Clone)]
struct Client {
    pass: String,
    name: String,
}

impl Client {
    fn new(n: String, p: String) -> Client {
        Client {name: n, pass: p}
    }
}

impl Identity for Client {
    fn get_name(self) -> String {
        self.name
    }
    fn get_secret(self) -> String {
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

    let bf = get_cipher();
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
                        Ok(_) => println!("Message sent"),
                        Err(e) => println!("Message not sent: {}", e),
                    }
                },
                None => {
                    println!("Authentication failure");
                },

            },
        Err(e) => println!("Can not clone stream: {}", e),
    }
}

fn auth_client<I>(mut stream: TcpStream) -> Option<Client> {
    let mut reader = get_buf_reader(stream.try_clone().unwrap());
    let challenge = generate_challenge();
    let mut reader_buffer = String::new();

    match send_id_request(stream.try_clone().unwrap(), challenge.clone()) {
        Ok(_) => 
        {
            match reader.read_line(&mut reader_buffer) {
                Ok(n) => info!("Read {} as identity line", n),
                Err(e) => warn!("Could not read identity: {}", e),
            }
            let client_identity_pretended = get_client_local_identity(remove_newline(reader_buffer.clone()));
            info!("Identity pretended: {}", client_identity_pretended.clone().get_name());

            let challenge_response_exp: Challenge = client_expected_challenge_response(client_identity_pretended.clone(), challenge);
            info!("Challenge expected: {:?}", challenge_response_exp.clone());

            reader_buffer.clear();
            match reader.read_line(&mut reader_buffer) {
                Ok(n) => info!("Read {} as challenge response line", n),
                Err(e) => warn!("Could not read challenge response: {}", e),
            }
            let challenge_response_buf: Challenge =
                base64::decode(&remove_newline(reader_buffer.clone()))
                .unwrap_or_else(|e| {error!("Can not decode {}: {}", reader_buffer, e); panic!()});
            info!("Challenge received: {:?}", challenge_response_buf.clone());

            if challenge_response_buf == challenge_response_exp {
                info!("Client authenticated");
                stream.write("Client authenticated\n".as_bytes()).expect("Error");
                Some::<Client>(client_identity_pretended)
            } else {
                info!("Authentication failure. Aborting.");
                let buf = "Authentication failure. Aborting.\n".to_string();
                match stream.write(buf.as_bytes()) {
                    Ok(_) => println!("NAUTH sent"),
                    Err(e) => println!("NAUTH not sent: {}", e),
                };
                None
            }
        }
        Err(e) => {
            println!("ID_REQ not sent: {}", e);
            None
        }
    }
}

fn client_expected_challenge_response<I>(i: I, challenge: Challenge) -> Challenge where I: Identity{
    challenge
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
    let buf = "Please identify yourself\n".to_string()
        + &"Challenge is: \""
        + &base64::encode(&challenge)
        + &"\"\n";
    stream.write(buf.as_bytes()) 
}

fn get_client_local_identity(s: String) -> Client {
    Client::new(s.clone(), s) 
}

fn remove_newline(s: String) -> String {
    let mut my_s = s.clone();
    my_s.pop();
    my_s
}

fn get_cipher() -> Blowfish {

    let key = vec![2, 0, 0, 0];
    Blowfish::new(key.as_slice())
}

fn start_logger() {
    env_logger::init();
    info!("Logger started");
}

fn get_buf_reader(stream: TcpStream) -> BufReader<TcpStream> {
    BufReader::new(stream)
}
