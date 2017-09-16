extern crate rfs;
use rfs::{message, message_signer, rfs_client, rfs_common};
#[macro_use]
extern crate log;
extern crate env_logger;

fn main() {
    start_logger();

    match rfs_client::RfsClientSession::new(get_address(), "client".to_lowercase(), get_client_key()) {
        Some(c) => c.disconnect().expect("Disconnection failed"),
        None => (),
    };

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

fn get_client_key() -> rfs_common::BlowfishKey {
    vec![3, 0, 0, 0]
}

fn get_address() -> String {
    info!("Address is localhost:4242");
    String::from("localhost:4242")
}

fn start_logger() {
    match env_logger::init() {
        Ok(()) => info!("Logger started"),
        Err(e) => print!("Error during logger initialisation. Reason: {}", e),
    }
}
