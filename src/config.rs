//! This module defines configuration related structure and functions. Basically, our configuration
//! is just a list of clients and servers with relevant details (keys, address, etc..).

use base64;
use rfs_common::{Identity, Named, BlowfishKey, get_buf_reader};
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::BufRead;
use std::path::Path;
use std::error::Error;

/// Fields of the config, either a client or a server.
#[derive(Clone)]
pub enum Field {
    Client { name: String, key: BlowfishKey },
    Server {
        name: String,
        key: BlowfishKey,
        address: String,
        port: String,
    },
}

impl Named for Field {
    type Name = String;
    fn get_name(&self) -> &Self::Name {
        match self {
            &Field::Client { ref name, key: _ } => name,
            &Field::Server {
                ref name,
                key: _,
                address: _,
                port: _,
            } => name,
        }
    }
}

impl Identity for Field {
    fn get_secret(&self) -> &BlowfishKey {
        match self {
            &Field::Client { name: _, ref key } => key,
            &Field::Server {
                name: _,
                ref key,
                address: _,
                port: _,
            } => key,
        }
    }
}

/// A configuration, which can be retrieved by a name and updated.
pub trait Config {
    type Name;
    type Field: Named;
    type ErrorType: Error;
    fn get_from_name(&self, name: Self::Name) -> Result<&Self::Field, Self::ErrorType>;
    fn add_field(&mut self, f: Self::Field) -> Result<(), ()>;
}

/// A configuration for the RFS.
#[derive(Clone)]
pub struct RfsConfig {
    fields: HashMap<String, Field>,
}

impl RfsConfig {
    /// Construct a new empty configuration.
    pub fn new() -> Self {
        RfsConfig { fields: HashMap::new() }
    }

    pub fn get_server_address(&self, server_name: String) -> Option<String> {
        match self.get_from_name(server_name) {
            Ok(&Field::Client { name: _, key: _ }) => None,
            Ok(&Field::Server {
                   name: _,
                   key: _,
                   ref address,
                   ref port,
               }) => Some(address.clone() + ":" + &port),
            Err(e) => {
                warn!{"Can not retrieve server address. Reason: {}", e};
                None
            }
        }
    }
}

impl Config for RfsConfig {
    type Name = String;
    type Field = Field;
    type ErrorType = RfsConfigError;

    fn get_from_name(&self, name: String) -> Result<&Field, RfsConfigError> {
        self.fields.get(&name).ok_or(RfsConfigError {
            kind: RfsConfigErrorKind::NoSuchName { name: name },
        })
    }

    fn add_field(&mut self, f: Field) -> Result<(), ()> {
        match self.fields.insert(f.get_name().clone(), f) {
            Some(_) => Err(()),
            None => Ok(()),
        }
    }
}

impl<T: AsRef<Path> + Display + Clone> From<T> for RfsConfig {
    fn from(p: T) -> Self {
        match File::open(p.clone()) {
            Ok(file) => {
                let mut conf = RfsConfig::new();
                let mut line_nb = 1;
                for line in get_buf_reader(file).lines() {
                    match line {
                        Ok(l) => {
                            let elem: Vec<&str> = l.split(':').collect();
                            match elem[0] {
                                "server" => {
                                    if elem.len() >= 5 {
                                        let new_field = Field::Server {
                                            name: String::from(elem[1]),
                                            key: base64::decode(elem[2]).unwrap(),
                                            address: String::from(elem[3]),
                                            port: String::from(elem[4]),
                                        };
                                        match conf.add_field(new_field) {
                                            Err(()) => warn!("Duplicate name \"{}\".", elem[1]),
                                            _ => (),
                                        }
                                    } else {
                                        warn!(
                                            "Line {} of file {} does not contain enough fields.",
                                            line_nb,
                                            p
                                        );
                                    }
                                }

                                "client" => {
                                    if elem.len() >= 3 {
                                        let new_field = Field::Client {
                                            name: String::from(elem[1]),
                                            key: base64::decode(elem[2]).unwrap(),
                                        };
                                        match conf.add_field(new_field) {
                                            Err(()) => warn!("Duplicate name \"{}\".", elem[1]),
                                            _ => (),
                                        }
                                    } else {
                                        warn!(
                                            "Line {} of file {} does not contain enough fields.",
                                            line_nb,
                                            p
                                        );
                                    }
                                }

                                _ => (),
                            }
                        }
                        Err(e) => warn!("Can't read line {} of file {}. Reason: {}", line_nb, p, e),
                    }
                    line_nb = line_nb + 1;
                }
                conf
            }
            Err(e) => {
                warn!("Could not open file {}. Reason: {}", p, e);
                RfsConfig::new()
            }
        }
    }
}

#[derive(Debug)]
enum RfsConfigErrorKind {
    NoSuchName { name: String },
}

#[derive(Debug)]
pub struct RfsConfigError {
    kind: RfsConfigErrorKind,
}

impl Display for RfsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RfsConfig Error: {:?}", self.kind)
    }
}

impl Error for RfsConfigError {
    fn description(&self) -> &str {
        match self.kind {
            RfsConfigErrorKind::NoSuchName { name: _ } => {
                "There is no client or serveur with such name in the config."
            }
        }
    }
}
