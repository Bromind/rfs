use std::net::TcpStream;
use std::io::Write;
use std::io::{BufReader, BufRead};
use std::error::Error;

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
use bincode::{serialize, deserialize, Bounded};

#[derive(Serialize, Deserialize, Debug)]
struct WriteFile {
    content: Vec<u8>,
    position: u64,
    filename: Vec<u8>,
}

trait Message: Sized {
    fn serialize(&self) -> Option<Vec<u8>>;
    fn deserialize(slice: &[u8]) -> Option<Self>;
}

impl WriteFile {
    fn new(content: Vec<u8>, position: u64, name: &str) -> Self {
        WriteFile {content: content, position: position, filename: name.as_bytes().to_vec()}
    }
}

impl Message for WriteFile {
    fn serialize (&self) -> Option<Vec<u8>> {
        let limit = Bounded(512);
        match serialize(&self, limit) {
            Ok(vec) => Some(vec),
            Err(e) => {
                warn!("Could not serialize WriteFile message. Reason: {}", e);
                None
            },
        }
    }

    fn deserialize(slice: &[u8]) -> Option<Self> {
        match deserialize(slice) {
            Ok(wf) => Some(wf),
            Err(e) => {
                warn!("Could not deserialize WriteFile message. Reason: {}", e);
                None
            },
        }
    }
}

#[derive(Debug)]
struct SignedMessage {
    serializedMessage: Vec<u8>,
    signature: Vec<u8>,
}

trait MessageSigner {
    fn sign<M: Message>(&self, message: M) -> Option<SignedMessage>;
    fn assert(&self, message: SignedMessage) -> Result<(), MessageSignerError>;
}

#[derive(Debug)]
enum MessageSignerErrorKind {
    SignatureDontMatch,
}

#[derive(Debug)]
struct MessageSignerError {
    kind: MessageSignerErrorKind,
}

impl std::fmt::Display for MessageSignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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

struct BlowfishSigner {
    bf: Blowfish,
}

impl BlowfishSigner {
    fn new(bfk: BlowfishKey) -> Self {
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
                Some(SignedMessage {serializedMessage: v, signature: out_buf.to_vec()})
            },
            None => None,
        }
    }

    fn assert(&self, message: SignedMessage) -> Result<(), MessageSignerError> {
        let mut xor: u8 = 0;
        for byte in message.serializedMessage {
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

fn main() {
    start_logger();
    connect_server();

    let message = WriteFile::new(vec![1, 2, 3, 4, 5], 0, "filename");
    let bfs = BlowfishSigner::new(get_client_key());
    match bfs.sign(message) {
        Some(sm) => {
            match bfs.assert(sm) {
                Ok(()) => print!("ok"),
                Err(e) => print!("{}", e),
            }
        },
        None => {panic!(); ()},
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


