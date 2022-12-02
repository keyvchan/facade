use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes_gcm::{aead::Payload, Nonce};
use chrono::Utc;
use crc::{Crc, CRC_32_ISO_HDLC};
use log::trace;
use md5::Digest;
use rand::Rng;
use sha2::Sha256;
use uuid::uuid;

/// KDF receives a bytes array and return a bytes array
pub(crate) fn kdf(key: Vec<u8>, path: Vec<Vec<u8>>) -> Vec<u8> {
    {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<Sha256>::new_from_slice("VMessAEAD".as_bytes())
            .expect("HMAC can take key of any size");

        for p in path {
            mac.update(&p);
        }

        mac.update(&key);
        mac.finalize().into_bytes().to_vec()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ID {
    pub(crate) id: [u8; 16],
    pub(crate) cmd_key: [u8; 16],
}

impl ID {
    pub fn cmd_key(&self) -> [u8; 16] {
        self.cmd_key
    }

    pub fn new(id: [u8; 16]) -> Self {
        // we need a cmdkey
        let mut md5_hasher = md5::Md5::new();
        md5_hasher.update(id);
        md5_hasher.update(uuid!("c48619fe-8f02-49e0-b9e9-edf763e17e21"));
        let cmd_key: [u8; 16] = md5_hasher
            .finalize()
            .to_vec()
            .try_into()
            .expect("digest length is 16");

        Self { id, cmd_key }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct EAuID {
    timestamp: u64,
    random: [u8; 4],
    crc: [u8; 4],
}

impl EAuID {
    pub fn new(timestamp: Option<u64>, random: Option<[u8; 4]>) -> Self {
        // check if the timestamp is valid
        let timestamp = match timestamp {
            Some(t) => t,
            None => Utc::now().timestamp() as u64,
        };

        // check random
        let random = match random {
            Some(r) => r,
            None => rand::thread_rng().gen(),
        };
        let calculate_buffer = [timestamp.to_be_bytes().as_slice(), random.as_slice()].concat();

        // calculate crc32
        let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);

        EAuID {
            timestamp,
            random,
            crc: crc.checksum(&calculate_buffer).to_be_bytes(),
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
        let key = kdf(key.to_vec(), vec![b"AES Auth ID Encryption".to_vec()]);
        trace!("key: {:?}", key);
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

        let nonce: [u8; 8] = rand::thread_rng().gen();
        let mut aead_payload_length_serialize_buffer = Vec::new();

        let header_payload_data_len = data.len() as u16;

        aead_payload_length_serialize_buffer
            .extend_from_slice(&header_payload_data_len.to_be_bytes());

        let aead_payload_length_serialized_byte = aead_payload_length_serialize_buffer;
        let mut payload_header_length_aead_encrypted = Vec::new();

        {
            use aes_gcm::{aead::Aead, KeyInit};
            let payload_header_length_aead_key = &kdf(
                key.to_vec(),
                vec![
                    b"VMess Header AEAD Key_Length".to_vec(),
                    au_id.to_vec(),
                    nonce.to_vec(),
                ],
            )[..16];

            let payload_header_length_aead_nonce = &kdf(
                key.to_vec(),
                vec![
                    b"VMess Header AEAD Nonce_Length".to_vec(),
                    au_id.to_vec(),
                    nonce.to_vec(),
                ],
            )[..12];

            let payload_header_aead =
                aes_gcm::Aes128Gcm::new(payload_header_length_aead_key.into());

            let payload = Payload {
                msg: &aead_payload_length_serialized_byte,
                aad: au_id.as_ref(),
            };
            payload_header_length_aead_encrypted = payload_header_aead
                .encrypt(Nonce::from_slice(payload_header_length_aead_nonce), payload)
                .expect("encryption failure!");
        }

        let mut payload_header_aead_encrypted = Vec::new();

        {
            use aes_gcm::{aead::Aead, KeyInit};
            let payload_header_aead_key = &kdf(
                key.to_vec(),
                vec![
                    b"VMess Header AEAD Key".to_vec(),
                    au_id.to_vec(),
                    nonce.to_vec(),
                ],
            )[..16];

            let payload_header_aead_nonce = &kdf(
                key.to_vec(),
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
