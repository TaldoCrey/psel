use std::fs;
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::prelude::*;
use std::thread;
use std::path::Path;
use std::sync::Arc;
use rand::Rng;
use sha2::{Sha256, Digest};


/// Returns a random String
/// 
/// # Arguments
/// 
/// * `size: usize` - Limit the size of the string generated.
/// * `charset: &[u8]` - Reference to our charset database as bytes.
fn generate_secret_key_string(size: usize, charset: &[u8]) -> String {
    let mut rng = rand::rng();
    (0..size).map(|_|{
        let i = rng.random_range(0..charset.len());
        charset[i] as char
    }).collect()
}


fn main() {
    const SECRET_KEY_CHARSET: &[u8] = b"ABCDEFGIJKLMNOPQRTUVWXYZ\
                                        abcdefghijklmnopqrstuvwxyz\
                                        0123456789\
                                        !@#$%&*()-=[]{},.;?<>";
    
    let secret_key_string = generate_secret_key_string(16, SECRET_KEY_CHARSET);
    
    let mut hasher = Sha256::new();
    hasher.update(secret_key_string.as_bytes());
    let hash_as_bytes = hasher.finalize();
    let secret_key = hex::encode(hash_as_bytes);
    let arc_secret_key = Arc::new(secret_key);
}
