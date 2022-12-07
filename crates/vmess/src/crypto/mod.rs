use dyn_clone::DynClone;
use sha2::{Digest, Sha256};
use std::iter::Iterator;

/// Hash is a trait which emulates the hash.Hash interface in Go.
trait Hash: DynClone {
    /// write adds more data to the running hash.
    fn write(&mut self, data: Vec<u8>);

    /// sum appends the current hash to b and returns the resulting slice.
    /// This does not change the underlying hash state.
    fn sum(&mut self, i: Option<Vec<u8>>) -> Vec<u8>;

    /// reset resets the Hash to its initial state.
    fn reset(&mut self);

    /// size returns the number of bytes Sum will return.
    fn size(&self) -> usize;

    /// block_size returns the hash's underlying block size.
    fn block_size(&self) -> usize;
}

/// Hmac is a struct which emulates the hmac.Hmac struct in Go.
/// marshalable option is not implemented.
#[derive(Clone)]
struct Hmac {
    /// opad is the outer padding.
    opad: Vec<u8>,
    /// ipad is the inner padding.
    ipad: Vec<u8>,
    /// inner is the inner hash.
    inner: Box<dyn Hash>,
    /// outer is the outer hash.
    outer: Box<dyn Hash>,
}

impl Hash for Hmac {
    fn write(&mut self, data: Vec<u8>) {
        self.inner.write(data);
    }

    fn sum(&mut self, input: Option<Vec<u8>>) -> Vec<u8> {
        // TODO: we shoul check if i is none
        let (orig_len, input) = match input {
            Some(i) => (i.len(), i),
            None => (0, vec![].to_vec()),
        };
        let input = self.inner.sum(Some(input));
        self.outer.reset();
        self.outer.write(self.opad.clone());

        self.outer.write(input[orig_len..].to_vec());
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

dyn_clone::clone_trait_object!(Hash);

impl Hmac {
    // emulates the hmac.New function in Go.
    fn new_hasher(hasher: Box<dyn Hash>, mut key: Vec<u8>) -> Box<dyn Hash> {
        // new hash
        // FIXME: memory allocation should be optimized.
        let mut outer = hasher.clone();
        let mut inner = hasher;

        let block_size = inner.block_size();
        let mut ipad = vec![0; block_size];
        let mut opad = vec![0; block_size];
        if key.len() > block_size {
            outer.write(key);
            key = outer.sum(None).to_vec();
        }

        ipad[0..key.len()].copy_from_slice(key.as_slice());
        (0..ipad.len()).for_each(|i| {
            ipad[i] ^= 0x36;
        });
        opad[0..key.len()].copy_from_slice(key.as_slice());
        (0..opad.len()).for_each(|i| {
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

/// Sha256Hasher wraps the sha256 hasher in sha2. It implements the Hash trait.
#[derive(Clone)]
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

/// calculate the kdf for given key and path
pub(crate) fn kdf(key: &[u8], path: Vec<Vec<u8>>) -> Vec<u8> {
    // TODO: hard coded token shoule be in a seperate file
    let mut mac = Hmac::new_hasher(
        Box::new(Sha256Hasher::new()),
        "VMess AEAD KDF".as_bytes().to_vec(),
    );

    for x in path.iter() {
        // feed the calculated mac1 to a new hasher, in reverse order
        let new_mac = Hmac::new_hasher(mac, x.to_vec());
        mac = new_mac;
    }

    mac.write(key.to_vec());

    mac.sum(None)
}
