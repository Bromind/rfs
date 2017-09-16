#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rfs;
use rfs::rfs_server::*;

fn main() {
    start_logger();
    match RfsServer::new(get_address()) {
        Some(s) => s.listen(),
        None => {print!("Error"); ()},
    }

}

fn start_logger() {
    match env_logger::init() {
         Ok(()) => info!("Logger started"),
         Err(e) => print!("Error during logger initialisation. Reason: {}", e),
    }
}

fn get_address() -> String {
    String::from("localhost:4242")
}
