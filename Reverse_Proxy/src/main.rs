use std::net::TcpListener;
use std::net::TcpStream;
use std::io::prelude::*;
use std::thread;
use std::path::Path;
use std::sync::{Arc, Mutex};
use sha2::{Sha256, Digest};

type SharedSecret = Arc<Mutex<Option<String>>>;

/// Print a custom pattern message on concole
/// 
/// # Arguments
/// 
/// * `message: String` - Message that will be printed out.
fn report(message: String) -> () {
    println!("[SERVER] :: {}", message);
}

fn main() {
    let listener = TcpListener::bind("0.0.0.0:2006").unwrap();

    let secret_state: SharedSecret = Arc::new(Mutex::new(None));

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        let secret_state_clone = Arc::clone(&secret_state);
        thread::spawn(move || {
            proxy_handler(stream, secret_state_clone);
        });
    }
}
