#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rfs;
use rfs::rfs_server::*;
use rfs::config::RfsConfig;

fn main() {
    start_logger();
    let config = RfsConfig::from("assets/rfs_config");
    match RfsServer::new(String::from("srv1"), config) {
        Some(s) => s.listen(),
        None => {
            print!("Error");
            ()
        }
    }
}

fn start_logger() {
    match env_logger::init() {
        Ok(()) => info!("Logger started"),
        Err(e) => print!("Error during logger initialisation. Reason: {}", e),
    }
}
