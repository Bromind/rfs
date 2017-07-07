use std::net::TcpStream;
use std::net::TcpListener;
use std::io::Write;

extern crate rand;

extern crate generic_array;
pub use generic_array::GenericArray;

extern crate base64;

//extern crate crypto_hashes;
//use crypto_hashes::digest::Digest;

extern crate blowfish;
use blowfish::Blowfish;

extern crate block_cipher_trait;
use block_cipher_trait::{BlockCipher, BlockCipherVarKey};

trait Identity: Clone {
    fn get_secret(self) -> String;
}

type Challenge = [u8;8];

#[derive(Clone)]
struct Client {
    pass: String,
}

impl Client {
    fn new(s: String) -> Client {
        Client {pass: s}
    }
}

impl Identity for Client {
    fn get_secret(self) -> String {
        self.pass
    }
}

fn main() {
    match TcpListener::bind("localhost:4242") {
        Ok(listener) => {
            println!("Listener ready...");
            loop{
                println!("Waiting for a client, press ^C to abort");
                match listener.accept() {
                    Ok((socket, addr)) => {
                        println!("new tcp client: {:?}", addr);
                        handle_client(socket);
                        println!("Connection closed");
                    },
                    Err(e) => println!("error: {:?}", e)
                }
            }
        },
        Err(e) => println!("error: {:?}", e)
    }
}

fn handle_client(mut stream: TcpStream) {
    let message = "My messa";

    let bf = get_cipher();
    let mut out_buf = GenericArray::new();
    let in_buf = GenericArray::from_slice(message.as_bytes());
    bf.encrypt_block(&in_buf, &mut out_buf);

    match auth_client::<Client>(stream.try_clone().unwrap()) {
        Some(_) => {
            stream.write("Message chiffré\n".as_bytes()).expect("Error");
            stream.write(base64::encode(&out_buf.to_vec()).as_bytes()).expect("Error sending Blowfish");
            stream.write("\n".as_bytes()).expect("Error");
        },
        None => println!("Authentication failure"),
    }
}

fn auth_client<I>(mut stream: TcpStream) -> Option<Client> {
    let challenge = generate_challenge();
    send_id_request(stream.try_clone().unwrap(), challenge);

    let client_identity_pretended = get_client_local_identity(stream_read_line(stream.try_clone().unwrap()));
    let mut challenge_response_buf = stream_read_line(stream.try_clone().unwrap());
    let challenge_response_exp = client_expected_challenge_response(client_identity_pretended.clone(), challenge);
    challenge_response_buf.pop(); // remove <LF> (line feed)
    challenge_response_buf.pop(); // remove <CR> (carriage return)

    if challenge_response_buf == challenge_response_exp {
        stream.write("Client authenticated\n".as_bytes()).expect("Error");
        Some::<Client>(client_identity_pretended)
    } else {
        stream.write("Authentication failure: \nExpected: ".as_bytes()).expect("Error");
        stream.write(challenge_response_exp.as_bytes()).expect("Error");
        stream.write("\nFound:    ".as_bytes()).expect("Error");
        stream.write(challenge_response_buf.as_bytes()).expect("Error");
        stream.write("\nAborting\n".as_bytes()).expect("Error");
        println!("{:?}", challenge_response_buf.as_bytes());
        println!("{:?}", challenge_response_exp.as_bytes());
        None
    }
}

fn client_expected_challenge_response<I>(i: I, challenge: Challenge) -> String where I: Identity{
    base64::encode(&challenge)
}

fn generate_challenge() -> Challenge {
    use rand::os::OsRng;
    use rand::Rng;

    let mut rng = OsRng::new().unwrap();
    let mut buf: [u8; 8] = [0; 8];
    rng.fill_bytes(&mut buf);
    buf
}

fn send_id_request(mut stream: TcpStream, challenge: Challenge) {
    stream.write("Please identify yourself\n".as_bytes()).expect("Error");
    stream.write("Challenge is: \"".as_bytes()).expect("Error");
    stream.write(base64::encode(&challenge).as_bytes()).expect("Error");
    stream.write("\"\n".as_bytes()).expect("Error");
}

fn get_client_local_identity(s: String) -> Client {
    Client::new(s) 
}

fn stream_read_line(stream: TcpStream) -> String {
    use std::io::{BufReader, BufRead};

    let mut buf = BufReader::new(stream);
    let mut to_ret = String::new();
    buf.read_line(&mut to_ret).unwrap();
    to_ret
}

fn get_cipher() -> Blowfish {

    let key = vec![2, 0, 0, 0];
    Blowfish::new(key.as_slice())
}
