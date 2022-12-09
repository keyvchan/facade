use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes_gcm::{aead::Payload, Nonce};
use chrono::Utc;
use crc::{Crc, CRC_32_ISO_HDLC};
use log::trace;
use md5::{Digest, Md5};
use rand::Rng;
use uuid::Uuid;

use crate::crypto::kdf;

#[derive(Debug, Default, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct ID {
    pub(crate) id: Uuid, // some what the id is a u8 array that length is 16
    pub(crate) cmd_key: [u8; 16],
}

const HASH_SEED: &str = "c48619fe-8f02-49e0-b9e9-edf763e17e21";

impl ID {
    /// Generate a new ID for given user id
    /// the cmd key is compose by a md5 hash of two parts
    /// 1. the id, which is the bytes representation of the uuid in u128
    /// 2. a hard-coded uuid, which is a bytes array that convert from uuid string directly
    pub fn new(id: Uuid) -> Self {
        let first_part = id.as_u128().to_be_bytes();
        trace!("first_part: {:?}", first_part);

        let second_part = HASH_SEED.as_bytes();

        trace!("second part: {:?}", second_part);
        // we need a cmdkey
        let mut md5_hasher = Md5::new();
        md5_hasher.update(first_part.as_slice());
        md5_hasher.update(second_part);
        let cmd_key = md5_hasher.finalize();
        trace!("cmd_key: {:?}", cmd_key);

        Self {
            id,
            cmd_key: cmd_key.to_vec().try_into().unwrap(),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct EAuID {
    timestamp: u64,
    random: [u8; 4],
    crc: [u8; 4],
}

impl EAuID {
    /// Generate a new EAuID
    pub fn new(timestamp: Option<u64>, random: Option<[u8; 4]>) -> Self {
        // check if the timestamp is valid
        let timestamp = match timestamp {
            Some(t) => t,
            None => Utc::now().timestamp() as u64,
        };
        trace!("timestamp: {}", timestamp);

        // check random
        let random = match random {
            Some(r) => r,
            None => rand::thread_rng().gen(),
        };
        let calculate_buffer = [timestamp.to_be_bytes().as_slice(), random.as_slice()].concat();
        trace!("calculate_buffer: {:?}", calculate_buffer);

        // calculate crc32
        let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC)
            .checksum(calculate_buffer.as_slice())
            .to_be_bytes();
        trace!("crc: {:?}", crc);

        EAuID {
            timestamp,
            random,
            crc,
        }
    }

    pub fn to_bytes(self) -> [u8; 16] {
        [
            self.timestamp.to_be_bytes().as_slice(),
            self.random.as_slice(),
            self.crc.as_slice(),
        ]
        .concat()
        .try_into()
        .expect("length is 16")
    }

    pub fn encrypt(&self, key: &[u8; 16]) -> [u8; 16] {
        // key should add salt
        let key = kdf(key.as_ref(), vec![b"AES Auth ID Encryption".to_vec()]);
        trace!("key after kdf: {:?}", key);
        assert_eq!(
            key,
            vec![
                130, 13, 246, 219, 49, 125, 34, 40, 145, 67, 196, 93, 14, 181, 70, 54, 205, 247,
                114, 68, 46, 5, 244, 195, 165, 84, 229, 110, 123, 39, 141, 58
            ],
            "key is not correct"
        );
        let key: [u8; 16] = key.as_slice()[..16].try_into().expect("length is 16");

        let cipher = <aes::Aes128 as aes_gcm::KeyInit>::new((&key).into());

        let mut block = GenericArray::from(self.to_bytes());
        cipher.encrypt_block(&mut block);
        block.into()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AEADHeader {
    pub(crate) au_id: EAuID,
}

impl AEADHeader {
    pub fn new() -> Self {
        AEADHeader {
            au_id: EAuID::new(None, None),
        }
    }

    pub fn seal(&self, id: ID, data: &[u8]) -> Vec<u8> {
        let key = id.cmd_key;
        let au_id = self.au_id.encrypt(&key);
        trace!("au_id: {:?}", au_id);

        let nonce: [u8; 8] = rand::thread_rng().gen();
        let mut aead_payload_length_serialize_buffer = Vec::new();

        let header_payload_data_len = data.len() as u16;

        aead_payload_length_serialize_buffer
            .extend_from_slice(&header_payload_data_len.to_be_bytes());

        let aead_payload_length_serialized_byte = aead_payload_length_serialize_buffer;
        let payload_header_length_aead_encrypted;

        {
            use aes_gcm::{aead::Aead, KeyInit};
            let payload_header_length_aead_key = &kdf(
                key.as_ref(),
                vec![
                    b"VMess Header AEAD Key_Length".to_vec(),
                    au_id.to_vec(),
                    nonce.to_vec(),
                ],
            )[..16];
            trace!(
                "payload_header_length_aead_key: {:?}",
                payload_header_length_aead_key
            );

            let payload_header_length_aead_nonce = &kdf(
                key.as_ref(),
                vec![
                    b"VMess Header AEAD Nonce_Length".to_vec(),
                    au_id.to_vec(),
                    nonce.to_vec(),
                ],
            )[..12];
            trace!(
                "payload_header_length_aead_nonce: {:?}",
                payload_header_length_aead_nonce
            );

            let payload_header_aead =
                aes_gcm::Aes128Gcm::new(payload_header_length_aead_key.into());

            let payload = Payload {
                msg: &aead_payload_length_serialized_byte,
                aad: au_id.as_ref(),
            };
            payload_header_length_aead_encrypted = payload_header_aead
                .encrypt(Nonce::from_slice(payload_header_length_aead_nonce), payload)
                .expect("encryption failure!");
            trace!(
                "payload_header_length_aead_encrypted: {:?}",
                payload_header_length_aead_encrypted
            );
        }

        let payload_header_aead_encrypted;

        {
            use aes_gcm::{aead::Aead, KeyInit};
            let payload_header_aead_key = &kdf(
                key.as_ref(),
                vec![
                    b"VMess Header AEAD Key".to_vec(),
                    au_id.to_vec(),
                    nonce.to_vec(),
                ],
            )[..16];

            let payload_header_aead_nonce = &kdf(
                key.as_ref(),
                vec![
                    b"VMess Header AEAD Nonce".to_vec(),
                    au_id.to_vec(),
                    nonce.to_vec(),
                ],
            )[..12];

            let payload_header_aead = aes_gcm::Aes128Gcm::new(payload_header_aead_key.into());

            let payload = Payload {
                msg: data,
                aad: au_id.as_ref(),
            };
            payload_header_aead_encrypted = payload_header_aead
                .encrypt(Nonce::from_slice(payload_header_aead_nonce), payload)
                .expect("encryption failure!");
        }

        let mut output_buffer = Vec::new();

        output_buffer.extend_from_slice(au_id.as_ref());
        output_buffer.extend_from_slice(&payload_header_length_aead_encrypted);
        output_buffer.extend_from_slice(&nonce);
        output_buffer.extend_from_slice(&payload_header_aead_encrypted);

        output_buffer
    }
}
