use std::net::TcpStream;
use std::io::Write;
use std::io::{BufReader, BufRead};

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate base64;


type Challenge = Vec<u8>;

fn main() {
    start_logger();
    connect_server();
}

fn start_logger() {
    env_logger::init();
    info!("Logger started");
}

fn connect_server() -> Option<TcpStream> {
    match TcpStream::connect(get_address()) {
        Ok(stream) => {
            info!("Connection successful");
            match get_challenge(stream.try_clone().unwrap()){
                Some(c) => {
                    info!("Challenge is: {:?}", c);
                    send_identity(stream.try_clone().unwrap(), String::from("Identity"));
                    send_challenge_response(stream.try_clone().unwrap(), c);
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

fn get_buf_reader(stream: TcpStream) -> BufReader<TcpStream> {
    BufReader::new(stream)
}

fn stream_read_line(stream: TcpStream) -> String {
    let mut buf = BufReader::new(stream);
    let mut to_ret = String::new();
    buf.read_line(&mut to_ret).unwrap();
    to_ret
}
