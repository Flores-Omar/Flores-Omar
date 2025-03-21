use rscam::{Camera, Config};
use aes::{Aes128, Aes192, Aes256};
use aes::cipher::{BlockEncrypt, KeyIvInit, generic_array::GenericArray};
use aes::cipher::{StreamCipher, NewCipher};
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::block_modes::{Cbc, Cfb, Ofb, Ecb};
use aes::cipher::stream::Ctr128;
use rand::{thread_rng, Rng};
use std::net::UdpSocket;

// Define LFSR for key generation
fn lfsr(seed: u32, taps: u32, size: usize) -> Vec<u8> {
    let mut state = seed;
    let mut output = Vec::new();
    for _ in 0..size {
        let bit = (state & taps).count_ones() % 2;
        state = (state >> 1) | (bit << 31);
        output.push((state & 0xFF) as u8);
    }
    output
}

fn encrypt_data(buffer: &mut Vec<u8>, key: &[u8], iv: &[u8], mode: &str, key_size: usize) {
    match (mode, key_size) {
        ("CBC", 16) => {
            let cipher = Cbc::<Aes128, Pkcs7>::new_from_slices(key, iv).unwrap();
            *buffer = cipher.encrypt_vec(buffer);
        },
        ("CBC", 24) => {
            let cipher = Cbc::<Aes192, Pkcs7>::new_from_slices(key, iv).unwrap();
            *buffer = cipher.encrypt_vec(buffer);
        },
        ("CBC", 32) => {
            let cipher = Cbc::<Aes256, Pkcs7>::new_from_slices(key, iv).unwrap();
            *buffer = cipher.encrypt_vec(buffer);
        },
        ("CFB", 16) => {
            let mut cipher = Cfb::<Aes128>::new_from_slices(key, iv).unwrap();
            cipher.apply_keystream(buffer);
        },
        ("CFB", 24) => {
            let mut cipher = Cfb::<Aes192>::new_from_slices(key, iv).unwrap();
            cipher.apply_keystream(buffer);
        },
        ("CFB", 32) => {
            let mut cipher = Cfb::<Aes256>::new_from_slices(key, iv).unwrap();
            cipher.apply_keystream(buffer);
        },
        ("OFB", 16) => {
            let mut cipher = Ofb::<Aes128>::new_from_slices(key, iv).unwrap();
            cipher.apply_keystream(buffer);
        },
        ("OFB", 24) => {
            let mut cipher = Ofb::<Aes192>::new_from_slices(key, iv).unwrap();
            cipher.apply_keystream(buffer);
        },
        ("OFB", 32) => {
            let mut cipher = Ofb::<Aes256>::new_from_slices(key, iv).unwrap();
            cipher.apply_keystream(buffer);
        },
        ("CTR", 16) => {
            let mut cipher = Ctr128::<Aes128>::new_from_slices(key, iv).unwrap();
            cipher.apply_keystream(buffer);
        },
        ("CTR", 24) => {
            let mut cipher = Ctr128::<Aes192>::new_from_slices(key, iv).unwrap();
            cipher.apply_keystream(buffer);
        },
        ("CTR", 32) => {
            let mut cipher = Ctr128::<Aes256>::new_from_slices(key, iv).unwrap();
            cipher.apply_keystream(buffer);
        },
        _ => panic!("Unsupported mode or key size"),
    }
}

fn main() {
    let mut camera = Camera::new("/dev/video0").expect("Failed to open camera");
    camera.start(&Config {
        interval: (1, 30),
        resolution: (640, 480),
        format: b"YUYV",
        ..Default::default()
    }).expect("Failed to start camera");

    let socket = UdpSocket::bind("0.0.0.0:8080").expect("Could not bind UDP socket");
    let target_addr = "192.168.1.100:8081";

    let key_size = 32; // Change between 16 (AES-128), 24 (AES-192), and 32 (AES-256)
    let encryption_mode = "CBC"; // Change between "CBC", "CFB", "OFB", "CTR"

    loop {
        let frame = camera.capture().expect("Failed to capture frame");
        let key = lfsr(0b10101010101010101010101010101010, 0b101, key_size);
        let iv = lfsr(0b11001100110011001100110011001100, 0b110, 16);
        let mut buffer = frame.to_vec();
        
        encrypt_data(&mut buffer, &key, &iv, encryption_mode, key_size);
        
        socket.send_to(&buffer, target_addr).expect("Failed to send data");
    }
}
