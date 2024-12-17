//! This module implements fast serde for reading and writing
//! key objects requires for proof generation and verification.
//! With WASM in particular, serializing via standard binary serializers
//! like bincode causes a dramatic decrease in performance. This simple
//! serializers parses in bytes very efficiently.
//!
//! In the future, it can be extended to do direct memory access to the
//! javascript runtime. For now it does a single copy of the data into
//! the rust runtime.

use std::io::{Cursor, Read};

use thiserror::Error;

pub static MAGIC_NUMBER: [u8; 4] = [0x50, 0x4C, 0x55, 0x54];
pub enum SerdeByteTypes {
    AuxParams = 0x01,
    UniversalKZGParam = 0x02,
    CommitmentKey = 0x03,
    ProverParams = 0x04
}

#[derive(Debug, Error)]
pub enum SerdeByteError {
    #[error("{}", "invalid magic number")]
    InvalidMagicNumber,
    #[error("{}", "invalid serde type")]
    InvalidSerdeType,
    #[error("{}", "invalid section count")]
    InvalidSectionCount,
    #[error("{}", "invalid section type")]
    InvalidSectionType,
    #[error("{}", "invalid section size")]
    InvalidSectionSize,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    BincodeError(#[from] Box<bincode::ErrorKind>),
    #[error("{}", "g1 decode error")]
    G1DecodeError,
    #[error("{}", "g2 decode error")]
    G2DecodeError,
}

/// A trait for fast conversions to bytes
pub trait FastSerde: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SerdeByteError>;

    fn validate_header(
        cursor: &mut Cursor<&Vec<u8>>,
        expected_type: SerdeByteTypes,
        expected_sections: u8,
    ) -> Result<(), SerdeByteError> {
        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic)?;
        if magic != MAGIC_NUMBER {
            return Err(SerdeByteError::InvalidMagicNumber);
        }

        let mut serde_type = [0u8; 1];
        cursor.read_exact(&mut serde_type)?;
        if serde_type[0] != expected_type as u8 {
            return Err(SerdeByteError::InvalidSerdeType);
        }

        let mut num_sections = [0u8; 1];
        cursor.read_exact(&mut num_sections)?;
        if num_sections[0] != expected_sections {
            return Err(SerdeByteError::InvalidSectionCount);
        }

        Ok(())
    }

    fn read_section_bytes(
        cursor: &mut Cursor<&Vec<u8>>,
        expected_type: u8,
    ) -> Result<Vec<u8>, SerdeByteError> {
        let mut section_type = [0u8; 1];
        cursor.read_exact(&mut section_type)?;
        if section_type[0] != expected_type {
            return Err(SerdeByteError::InvalidSectionType);
        }

        let mut section_size = [0u8; 4];
        cursor.read_exact(&mut section_size)?;
        let size = u32::from_le_bytes(section_size) as usize;
        let mut section_data = vec![0u8; size];
        cursor.read_exact(&mut section_data)?;

        Ok(section_data)
    }

    fn write_section_bytes(out: &mut Vec<u8>, section_type: u8, data: &Vec<u8>) {
        out.push(section_type);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
}
