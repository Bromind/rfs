use blowfish::Blowfish;
use block_cipher_trait::BlockCipher;
use std::net::TcpStream;
use std::io::Write;
use std::io::{BufReader, BufRead};
use generic_array::GenericArray;
use std::net::Shutdown;
use base64;
use rfs_common::{Challenge, BlowfishKey, get_cipher, get_buf_reader};
use std::io::Error as IoError;

pub struct RfsClientSession {
    stream: TcpStream,
    client_name: String,
    client_key: BlowfishKey,
}

impl RfsClientSession{
    pub fn new(address: String, name: String, key: BlowfishKey) -> Option<Self> {
        match connect_server(address, key.clone()) {
            Some(stream) => Some(RfsClientSession {stream: stream, client_name: name, client_key: key}),
            None => {warn!("Could not create RfsClientSession"); None},
        }
    }

    pub fn disconnect(&self) -> Result<(), IoError> {
        info!("Shutdown connection");
        self.stream.shutdown(Shutdown::Both)
    }
}

fn connect_server(address: String, key: BlowfishKey) -> Option<TcpStream> {
    let bf = get_cipher(key);
    match TcpStream::connect(address) {
        Ok(stream) => {
            info!("Connection successful");
            match get_challenge(stream.try_clone().unwrap()){
                Some(c) => {
                    info!("Challenge is: {:?}", c);
                    send_identity(stream.try_clone().unwrap(), String::from("Identity"));
                    let c_resp = get_challenge_response(c, bf);
                    send_challenge_response(stream.try_clone().unwrap(), c_resp);
                    Some(stream)
                },
                None => {
                    warn!("Could not get challenge");
                    None
                },
            }
        },
        Err(e) => {
            warn!("Error connecting to server. Reason: {}", e);
            None
        },
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

fn stream_read_line(stream: TcpStream) -> String {
    let mut buf = BufReader::new(stream);
    let mut to_ret = String::new();
    buf.read_line(&mut to_ret).unwrap();
    to_ret
}
