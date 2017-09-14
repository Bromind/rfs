use std::net::TcpStream;
use std::io::Write;
use std::io::{BufReader, BufRead};

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate base64;

extern crate generic_array;
use generic_array::GenericArray;

extern crate blowfish;
use blowfish::Blowfish;

extern crate block_cipher_trait;
use block_cipher_trait::{BlockCipher, BlockCipherVarKey};

type BlowfishKey = Vec<u8>;
type Challenge = Vec<u8>;

extern crate bincode;
#[macro_use]
extern crate serde_derive;

pub mod message;

pub mod message_signer;

fn main() {
    start_logger();
    connect_server();

    use message_signer::{BlowfishSigner, MessageSigner};
    let message = message::WriteFile::new(vec![1, 2, 3, 4, 5], 0, "filename");
    let bfs = BlowfishSigner::new(get_client_key());
    match bfs.sign(message) {
        Some(sm) => {
            match bfs.assert(sm) {
                Ok(()) => print!("ok"),
                Err(e) => print!("{}", e),
            }
        },
        None => {panic!()},
    };
}

fn start_logger() {
    match env_logger::init() {
        Ok(()) => info!("Logger started"),
        Err(e) => print!("Error during logger initialisation. Reason: {}", e),
    }
}

fn connect_server() -> Option<TcpStream> {
    let bf = get_cipher(get_client_key());
    match TcpStream::connect(get_address()) {
        Ok(stream) => {
            info!("Connection successful");
            match get_challenge(stream.try_clone().unwrap()){
                Some(c) => {
                    info!("Challenge is: {:?}", c);
                    send_identity(stream.try_clone().unwrap(), String::from("Identity"));
                    let c_resp = get_challenge_response(c, bf);
                    send_challenge_response(stream.try_clone().unwrap(), c_resp);
                },
                None => warn!("Could not get challenge"),
            }
            
            info!("Shutdown connection");
            stream.shutdown(std::net::Shutdown::Both).expect("shutdown failed");
        },
        Err(e) => warn!("Error connecting to server. Reason: {}", e),
    };
    None
}


fn get_address() -> String {
    info!("Address is localhost:4242");
    String::from("localhost:4242")
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
        },
        Err(e) => {
            warn!("Can not decode {}: {}", splitted_line_2, e);
            None
        },
    }
}

fn send_identity(mut stream: TcpStream, s: String) {
    stream.write(s.as_bytes());
    stream.write("\n".as_bytes());
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

fn get_buf_reader(stream: TcpStream) -> BufReader<TcpStream> {
    BufReader::new(stream)
}

fn stream_read_line(stream: TcpStream) -> String {
    let mut buf = BufReader::new(stream);
    let mut to_ret = String::new();
    buf.read_line(&mut to_ret).unwrap();
    to_ret
}

fn get_cipher(key: BlowfishKey) -> Blowfish {
    Blowfish::new(key.as_slice())
}

fn get_client_key() -> BlowfishKey {
    vec![3, 0, 0, 0]
}


