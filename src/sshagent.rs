use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::private::KeypairData;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("SSH encoding error: {0}")]
    SSHEncoding(#[from] ssh_encoding::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Command not supported ({command})")]
    UnsupportedCommand { command: u8 },
}

#[derive(Clone, PartialEq, Debug)]
pub enum Request {
    AddIdentity(AddIdentity),
}

impl Request {
    pub fn id(&self) -> u8 {
        match self {
            Request::AddIdentity(_) => 17,
        }
    }
}

impl Encode for Request {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        let payload_len = match self {
            Request::AddIdentity(e) => e.encoded_len()?,
        };

        Ok(payload_len + 1)
    }

    fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error> {
        self.id().encode(writer)?;

        match self {
            Request::AddIdentity(e) => e.encode(writer),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct AddIdentity {
    pub privkey: KeypairData,
    pub comment: String,
}

impl Encode for AddIdentity {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        let private_len = self.privkey.encoded_len()?;
        let comment_len = self.comment.encoded_len()?;

        Ok(private_len + comment_len)
    }

    fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error> {
        self.privkey.encode(writer)?;
        self.comment.encode(writer)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Response {
    Failure,
    Success,
}

impl Decode for Response {
    type Error = AgentError;

    fn decode(reader: &mut impl Reader) -> Result<Self, AgentError> {
        let message_type = u8::decode(reader)?;

        match message_type {
            5 => Ok(Self::Failure),
            6 => Ok(Self::Success),
            command => Err(AgentError::UnsupportedCommand { command }),
        }
    }
}

pub struct SSHAgent {
    socket: UnixStream,
}

impl SSHAgent {
    pub fn new() -> anyhow::Result<Self> {
        let agent_sock_path = std::env::var("SSH_AUTH_SOCK")?;
        Ok(Self {
            socket: UnixStream::connect(agent_sock_path)?,
        })
    }

    pub fn request(&mut self, request: Request) -> anyhow::Result<Response> {
        let mut buf = Vec::with_capacity(4096);

        let length = request.encoded_len()?;
        request.encode(&mut buf)?;

        self.socket.write_u32::<BigEndian>(length as u32)?;
        self.socket.write_all(&buf[..length])?;
        self.socket.flush()?;

        let length = self.socket.read_u32::<BigEndian>()? as usize;
        self.socket.read_exact(&mut buf[..length])?;

        let reader = &mut buf[..length].as_ref();
        let resp = Response::decode(reader)?;
        Ok(resp)
    }
}
