use bincode::{serialize, deserialize, Bounded};

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteFile {
    content: Vec<u8>,
    position: u64,
    filename: Vec<u8>,
}

pub trait Message: Sized {
    fn serialize(&self) -> Option<Vec<u8>>;
    fn deserialize(slice: &[u8]) -> Option<Self>;
}

impl WriteFile {
    pub fn new(content: Vec<u8>, position: u64, name: &str) -> Self {
        WriteFile {
            content: content,
            position: position,
            filename: name.as_bytes().to_vec(),
        }
    }
}

impl Message for WriteFile {
    fn serialize(&self) -> Option<Vec<u8>> {
        let limit = Bounded(512);
        match serialize(&self, limit) {
            Ok(vec) => Some(vec),
            Err(e) => {
                warn!("Could not serialize WriteFile message. Reason: {}", e);
                None
            }
        }
    }

    fn deserialize(slice: &[u8]) -> Option<Self> {
        match deserialize(slice) {
            Ok(wf) => Some(wf),
            Err(e) => {
                warn!("Could not deserialize WriteFile message. Reason: {}", e);
                None
            }
        }
    }
}
