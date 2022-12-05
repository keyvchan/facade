use sha2::{Digest, Sha256};

trait Hash {
    fn write(&mut self, data: Vec<u8>);
    fn sum(&mut self, i: Option<Vec<u8>>) -> Vec<u8>;
    fn reset(&mut self);
    fn size(&self) -> usize;
    fn block_size(&self) -> usize;
}

struct Hmac {
    opad: Vec<u8>,
    ipad: Vec<u8>,
    inner: Box<dyn Hash>,
    outer: Box<dyn Hash>,
}

impl Hash for Hmac {
    fn write(&mut self, data: Vec<u8>) {
        self.inner.write(data);
    }

    fn sum(&mut self, input: Option<Vec<u8>>) -> Vec<u8> {
        // we shoul check if i is none
        let (orig_len, input) = match input {
            Some(i) => (i.len(), i),
            None => (0, vec![].to_vec()),
        };
        self.outer.reset();
        self.outer.write(self.opad.clone());

        self.outer.sum(Some(input[0..orig_len].to_vec()))
    }

    fn reset(&mut self) {
        self.inner.reset();
        self.inner.write(self.ipad.clone());
        self.outer.reset();
        self.outer.write(self.opad.clone());
    }

    fn size(&self) -> usize {
        self.outer.size()
    }

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }
}

impl Hmac {
    fn new(hasher: fn() -> Box<dyn Hash>, mut key: Vec<u8>) -> Box<dyn Hash> {
        let mut outer = hasher();
        let mut inner = hasher();

        let block_size = inner.block_size();
        let mut ipad = vec![0; block_size];
        let mut opad = vec![0; block_size];
        if key.len() > block_size {
            outer.write(key);
            key = outer.sum(None).to_vec();
        }

        ipad[0..key.len()].copy_from_slice(key.as_slice());
        (0..key.len()).for_each(|i| {
            ipad[i] ^= 0x36;
        });
        opad[0..key.len()].copy_from_slice(key.as_slice());
        (0..key.len()).for_each(|i| {
            opad[i] ^= 0x5c;
        });
        inner.write(ipad.clone());

        Box::new(Hmac {
            opad,
            ipad: ipad.to_vec(),
            inner,
            outer,
        })
    }
}

struct Sha256Hasher {
    hasher: Sha256,
}

impl Hash for Sha256Hasher {
    fn write(&mut self, data: Vec<u8>) {
        self.hasher.update(data);
    }

    fn sum(&mut self, input: Option<Vec<u8>>) -> Vec<u8> {
        let mut hasher = self.hasher.clone();
        if let Some(i) = input {
            hasher.update(i);
        }
        hasher.finalize().to_vec()
    }

    fn reset(&mut self) {
        self.hasher = Sha256::new();
    }

    fn size(&self) -> usize {
        32
    }

    fn block_size(&self) -> usize {
        64
    }
}

impl Sha256Hasher {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }
}

fn sha256() -> Box<dyn Hash> {
    Box::new(Sha256Hasher::new())
}

pub fn kdf(key: Vec<u8>, path: Vec<Vec<u8>>) -> Vec<u8> {
    let mut mac = Hmac::new(sha256, "VMess AEAD KDF".as_bytes().to_vec());
    let final_vec = mac.sum(None);
    println!("{final_vec:?}");
    final_vec
}
