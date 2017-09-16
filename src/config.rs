//! This module defines configuration related structure and functions. Basically, our configuration
//! is just a list of clients and servers with relevant details (keys, address, etc..).

use base64;
use rfs_common::{Named, BlowfishKey, get_buf_reader};
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::io::BufRead;
use std::path::Path;

/// Fields of the config, either a client or a server.
#[derive(Clone)]
pub enum Field {
    Client{name: String, key: BlowfishKey}, 
    Server{name: String, key: BlowfishKey, address: String, port: String}, 
}

impl Named for Field {
    type Name = String;
    fn get_name(self) -> Self::Name {
        match self {
            Field::Client{name, key:_} => name.clone(),
            Field::Server{name, key:_, address:_, port:_} => name,
        }
    }
}

/// A configuration, which can be retrieved by a name and updated.
pub trait Config {
    type Name;
    type Field: Named;
    fn get_from_name(&self, name: Self::Name) -> Option<&Self::Field>;
    fn add_field(&mut self, f: Self::Field) -> Result<(), ()>;
}

/// A configuration for the RFS.
pub struct RfsConfig {
    fields: HashMap<String, Field>,
}

impl RfsConfig {
    /// Construct a new empty configuration.
    pub fn new() -> Self {
        RfsConfig {fields: HashMap::new()}
    }
}

impl Config for RfsConfig {
    type Name = String;
    type Field = Field;

    fn get_from_name(&self, name: String) -> Option<&Field> {
        self.fields.get(&name) 
    }

    fn add_field(&mut self, f: Field) -> Result<(), ()> {
        match self.fields.insert(f.clone().get_name(), f) {
            Some(_) => Err(()),
            None => Ok(()),
        }
    }
}

impl <T: AsRef<Path> + Display + Clone> From<T> for RfsConfig {
    fn from(p: T) -> Self {
        match File::open(p.clone()) {
            Ok(file) => {
                let mut conf = RfsConfig::new();
                let mut line_nb = 1;
                for line in get_buf_reader(file).lines(){
                    match line {
                        Ok(l) => {
                            let elem: Vec<&str> = l.split(':').collect();
                            match elem[0] {
                                "server" => {
                                    if elem.len() >= 5 {
                                        let new_field = Field::Server{name: String::from(elem[1]), key: base64::decode(elem[2]).unwrap(), address: String::from(elem[3]), port: String::from(elem[4])};
                                        match conf.add_field(new_field) {
                                            Err(()) => warn!("Duplicate name \"{}\".", elem[1]),
                                            _ => (),
                                        }
                                    } else {
                                        warn!("Line {} of file {} does not contain enough fields.", line_nb, p);
                                    }
                                },

                                "client" => {
                                    if elem.len() >= 3 {
                                        let new_field = Field::Client{name: String::from(elem[1]), key: base64::decode(elem[2]).unwrap()};
                                        match conf.add_field(new_field) {
                                            Err(()) => warn!("Duplicate name \"{}\".", elem[1]),
                                            _ => (),
                                        }
                                    } else {
                                        warn!("Line {} of file {} does not contain enough fields.", line_nb, p);
                                    }
                                },

                                _ => (),
                            }
                        },
                        Err(e) => warn!("Can't read line {} of file {}. Reason: {}", line_nb, p, e),
                    }
                    line_nb = line_nb+1;
                }
                conf
            },
            Err(e) => {
                warn!("Could not open file {}. Reason: {}", p, e);
                RfsConfig::new()
            },
        }
    }
}
