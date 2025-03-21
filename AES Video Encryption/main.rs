use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use aes::{Aes128, Aes192, Aes256};
use aes::cipher::{KeyIvInit, BlockDecrypt, StreamCipher, generic_array::GenericArray};
use aes::cipher::block_modes::{Cbc, Cfb, Ofb, Ecb};
use aes::cipher::stream::Ctr128;
use opencv::{prelude::*, imgcodecs, highgui, imgproc};
use rand::{thread_rng, Rng};

// LFSR for Key Generation
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

// Decryption Function
fn decrypt_data(buffer: &mut Vec<u8>, key: &[u8], iv: &[u8], mode: &str, key_size: usize) {
    match (mode, key_size) {
        ("CBC", 16) => { /* CBC AES-128 decryption here */ }
        ("CBC", 24) => { /* CBC AES-192 decryption here */ }
        ("CBC", 32) => { /* CBC AES-256 decryption here */ }
        ("CFB", 16) => { /* CFB AES-128 decryption here */ }
        ("CFB", 24) => { /* CFB AES-192 decryption here */ }
        ("CFB", 32) => { /* CFB AES-256 decryption here */ }
        ("OFB", 16) => { /* OFB AES-128 decryption here */ }
        ("OFB", 24) => { /* OFB AES-192 decryption here */ }
        ("OFB", 32) => { /* OFB AES-256 decryption here */ }
        ("CTR", 16) => { /* CTR AES-128 decryption here */ }
        ("CTR", 24) => { /* CTR AES-192 decryption here */ }
        ("CTR", 32) => { /* CTR AES-256 decryption here */ }
        _ => panic!("Unsupported mode or key size"),
    }
}

fn main() {
    let socket = UdpSocket::bind("0.0.0.0:8081").expect("Could not bind UDP socket");
    let key_size = 32;  // Must match sender (16, 24, or 32 for AES-128, AES-192, AES-256)
    let encryption_mode = "CBC";  // Must match sender's mode

    highgui::named_window("Decrypted Video", highgui::WINDOW_AUTOSIZE).unwrap();

    let mut buffer = vec![0; 65535]; // Large buffer for UDP packets

    loop {
        let (size, _) = socket.recv_from(&mut buffer).expect("Failed to receive data");
        let mut frame_data = buffer[..size].to_vec();

        let key = lfsr(0b10101010101010101010101010101010, 0b101, key_size);
        let iv = lfsr(0b11001100110011001100110011001100, 0b110, 16);

        decrypt_data(&mut frame_data, &key, &iv, encryption_mode, key_size);

        let image = imgcodecs::imdecode(&frame_data, imgcodecs::IMREAD_COLOR)
            .expect("Failed to decode image");

        highgui::imshow("Decrypted Video", &image).unwrap();
        highgui::wait_key(1).unwrap();
    }
}
