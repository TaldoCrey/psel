use std::fmt::format;
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

/// Print a custom pattern message on concole
/// 
/// # Arguments
/// 
/// * `message: String` - Message that will be printed out.
fn report(message: String) -> () {
    println!("[SERVER] :: {}", message);
}

/// Try to register a secret-key at proxy
/// 
/// # Arguments
/// 
/// * `secret: &str` - String reference that contains the secret-key.
/// 
/// ## Returns
/// Nothing if the registration is successfull
/// A String if any error occurr
fn register_with_proxy(secret: &str) -> Result<(), String> {
    match TcpStream::connect("0.0.0.0:2006") {
        Ok(mut stream) => {
            let request = format!(
                "POST /register-secret HTTP/1.1\r\n\
                Host: 0.0.0.0:2006\r\n\
                Content-Type: text/plain\r\n\
                Content-Length: {}\r\n\
                \r\n\
                {}",
                secret.len(),
                secret
            );

            stream.write(request.as_bytes()).unwrap();

            let mut response_buffer = [0; 512];
            stream.read(&mut response_buffer).map_err(|e|e.to_string());
            let response_str = String::from_utf8_lossy(&response_buffer);

            if response_str.starts_with("HTTP/1.1 200 OK") {
                report(format!("Secret Key has been setted up with proxy."));
                Ok(())
            } else {
                Err(format!("Secret Key registration have failed. Proxy's answer: {}", response_str))
            }
        },
        Err(e) => Err(format!("Connection with proxy have failed!"))
    }
}

fn handle_connection(mut stream: TcpStream, secret: Arc<String>) {
    
}

fn main() {
    const SECRET_KEY_CHARSET: &[u8] = b"ABCDEFGIJKLMNOPQRTUVWXYZ\
                                        abcdefghijklmnopqrstuvwxyz\
                                        0123456789\
                                        !@#$%&*()-=[]{},.;?<>";
    
    //Generates a random String
    let secret_key_string = generate_secret_key_string(16, SECRET_KEY_CHARSET);
    
    //Made a SHA-256 key with random String data
    let mut hasher = Sha256::new();
    hasher.update(secret_key_string.as_bytes());
    let hash_as_bytes = hasher.finalize();
    let secret_key = hex::encode(hash_as_bytes);

    report(format!("Secret Key Generated! >>> {}", &secret_key));

    while let Err(e) = register_with_proxy(&secret_key.as_str()) {
        eprintln!("[SERVER] :: Critical Error >> {}", e);
    }

    let arc_secret_key = Arc::new(secret_key);

    let listener =  TcpListener::bind("127.0.0.1:1445").unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let secret_key_clone = Arc::clone(&arc_secret_key);
        thread::spawn(move || {
            handle_connection(stream, secret_key_clone);
        });
    }
}
