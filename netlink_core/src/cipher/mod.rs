mod xor;

#[derive(Clone)]
pub enum Cipher {
    Safe(Box<rustp2p::cipher::Cipher>),
    Xor(xor::XORCipher),
}

impl Cipher {
    pub fn new_chacha20_poly1305(password: String) -> Self {
        Cipher::Safe(Box::new(rustp2p::cipher::Cipher::new_chacha20_poly1305(
            password,
        )))
    }
    pub fn new_aes_gcm(password: String) -> Self {
        Cipher::Safe(Box::new(rustp2p::cipher::Cipher::new_aes_gcm(password)))
    }
    pub fn new_xor(password: String) -> Self {
        Cipher::Xor(xor::XORCipher::new_password(&password))
    }
    pub fn decrypt(&self, extra_info: [u8; 12], payload: &mut [u8]) -> anyhow::Result<usize> {
        match self {
            Cipher::Safe(c) => c.decrypt(extra_info, payload),
            Cipher::Xor(c) => c.decrypt(extra_info, payload),
        }
    }
    pub fn encrypt(&self, extra_info: [u8; 12], payload: &mut [u8]) -> anyhow::Result<()> {
        match self {
            Cipher::Safe(c) => c.encrypt(extra_info, payload),
            Cipher::Xor(c) => c.encrypt(extra_info, payload),
        }
    }
    pub fn reserved_len(&self) -> usize {
        match self {
            Cipher::Safe(c) => c.reserved_len(),
            Cipher::Xor(c) => c.reserved_len(),
        }
    }
}
