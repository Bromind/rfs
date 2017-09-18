extern crate rfs;
use rfs::config::RfsConfig;
use rfs::rfs_client::{Client, RfsClientSession};
#[macro_use]
extern crate log;
extern crate env_logger;

fn main() {
    start_logger();

    let config = RfsConfig::from("assets/rfs_config");

    match RfsClientSession::new(String::from("srv1"), String::from("cli1"), config) {
        Some(mut c) => {
            c.connect();
            c.disconnect().expect("Disconnection failed");
        }
        None => (),
    };
}

fn start_logger() {
    match env_logger::init() {
        Ok(()) => info!("Logger started"),
        Err(e) => print!("Error during logger initialisation. Reason: {}", e),
    }
}
