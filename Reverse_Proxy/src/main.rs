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
    println!("[REVERSE PROXY] :: {}", message);
}
/// Container that store request data
/// 
/// # Arguments
/// All are String type:
/// * `sigature` - Proxy's Signature.
/// * `method` - Request's method.
/// * `uri` - Request's path.
/// * `host` - Request's host.
/// * `body` - Request's body.
#[allow(dead_code)]
struct Request {
    signature: String,
    method: String,
    uri: String,
    host: String,
    body: String
}

fn parse(request: String) -> Request {
    let main_header = request.lines().next().unwrap();
    let mut parts = main_header.split_whitespace();
    let method = parts.next().unwrap();
    let path = parts.next().unwrap();
    let host = "0.0.0.0:2006";
    let (_, body)  = request.split_once("\r\n\r\n").unwrap();

    Request {
        method: method.to_string(),
        signature: "N/A".to_string(),
        uri: path.to_string(),
        host: host.to_string(),
        body: body.to_string()
    }
}


fn proxy_handler(mut stream: TcpStream, secret_state: SharedSecret) {
    let mut buffer = [0; 4096];
    stream.read(&mut buffer).unwrap();
    let request_string = String::from_utf8_lossy(&buffer[..]);

    let mut request = parse(request_string.to_string());

    report(format!("Received new request => \n
                            Method: {}\nURI: {}\nHost: {}\n\nBody: {}\n",
                            request.method, request.uri, request.host, request.body));
    

    if request.method == "POST" && request.uri == "/register-secret" {
        let body = request.body.trim_end_matches('\0');

        let mut signature_key = secret_state.lock().unwrap();
        *signature_key = Some(body.to_string());

        report(format!("Received serve's key >>> {:?}", *signature_key));

        let response = "HTTP/1.1 200 OK\r\n\r\n";
        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    } else {
        let signature_key_guard = secret_state.lock().unwrap();
        let signature_key = match &*signature_key_guard {
            Some(s) => s.clone(),
            None => {
                let response = "HTTP/1.1 503 SERVICE UNAVAIBLE\r\n\r\nProxy not ready";
                stream.write(response.as_bytes()).unwrap();
                stream.flush().unwrap();
                return;
            }
        };
        drop(signature_key_guard);

        request.signature = signature_key;

        proxy_route(request);
    }
}

fn proxy_route(request: Request) {
    
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
