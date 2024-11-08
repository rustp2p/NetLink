pub fn simple_hash(input: &str) -> [u8; 32] {
    let mut result = [0u8; 32];
    let bytes = input.as_bytes();
    for (index, v) in result.iter_mut().enumerate() {
        *v = bytes[index % bytes.len()];
    }

    let mut state = 0u8;

    for (i, &byte) in bytes.iter().enumerate() {
        let combined = byte.wrapping_add(state).rotate_left((i % 8) as u32);
        result[i % 32] ^= combined;
        state = state.wrapping_add(byte).rotate_left(3);
    }

    for i in 0..32 {
        result[i] = result[i]
            .rotate_left((result[(i + 1) % 32] % 8) as u32)
            .wrapping_add(state);
        state = state.wrapping_add(result[i]).rotate_left(3);
    }

    result
}

#[derive(Clone)]
pub struct XORCipher {
    key: [u8; 32],
}

impl XORCipher {
    pub fn new_password(password: &str) -> Self {
        Self {
            key: simple_hash(password),
        }
    }
    pub fn reserved_len(&self) -> usize {
        0
    }
    pub fn decrypt(&self, extra_info: [u8; 12], payload: &mut [u8]) -> anyhow::Result<usize> {
        let key = &self.key;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i & 31] ^ extra_info[i & 7];
        }
        Ok(payload.len())
    }
    pub fn encrypt(&self, extra_info: [u8; 12], payload: &mut [u8]) -> anyhow::Result<()> {
        let key = &self.key;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i & 31] ^ extra_info[i & 7];
        }
        Ok(())
    }
}

#[test]
fn test_xor() {
    let c = XORCipher::new_password("password");
    let src = [3; 100];
    let mut data = src;
    c.encrypt([1; 12], &mut data).unwrap();
    println!("{:?}", data);
    let len = c.decrypt([1; 12], &mut data).unwrap();
    assert_eq!(&data[..len], &src[..len]);
}
