use crate::cipher::xor::XORCipher;
use std::io;

mod xor;

#[derive(Clone)]
pub enum Cipher {
    Safe(Box<rustp2p::cipher::Cipher>),
    Xor(XORCipher),
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
        Cipher::Xor(XORCipher::new_password(&password))
    }
    pub fn decrypt(&self, extra_info: [u8; 12], payload: &mut [u8]) -> io::Result<usize> {
        match self {
            Cipher::Safe(c) => c.decrypt(extra_info, payload),
            Cipher::Xor(c) => c.decrypt(extra_info, payload),
        }
    }
    pub fn encrypt(&self, extra_info: [u8; 12], payload: &mut [u8]) -> io::Result<()> {
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

#[test]
fn test_aes_gcm() {
    let c = Cipher::new_aes_gcm("password".to_string());
    let src = [3; 100];
    let mut data = src;
    let reserved_len = c.reserved_len();
    c.encrypt([1; 12], &mut data).unwrap();
    println!("{:?}", data);
    let len = c.decrypt([1; 12], &mut data).unwrap();
    assert_eq!(&data[..len], &src[..len]);
}

#[test]
fn test_chacha20_poly1305() {
    let c = Cipher::new_chacha20_poly1305("password".to_string());
    let src = [3; 100];
    let mut data = src;
    c.encrypt([1; 12], &mut data).unwrap();
    println!("{:?}", data);
    let len = c.decrypt([1; 12], &mut data).unwrap();
    assert_eq!(&data[..len], &src[..len]);
}
