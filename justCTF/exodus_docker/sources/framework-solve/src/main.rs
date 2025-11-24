use std::net::TcpStream;
use std::io::{Read, Write};
use std::str::from_utf8;
use std::{error::Error, fs};
use std::env;

/// the list of parameters that will be passed to the `solution::solve` function
const PARAMS_LIST: [(u8, u8); 2] = [
    (3, 0), // Coin<FUEL_CELL>
    (1, 2), // OtternautCapsule
];

fn prepare_params(params: Vec<(u8, u8)>) -> Vec<u8> {
    let mut serialized_params = Vec::with_capacity(params.len() * 2);
    for (x, y) in params {
        serialized_params.push(x);
        serialized_params.push(y);
    }
    serialized_params
}

fn send_after(stream: &mut TcpStream, expected: &str, data: Vec<u8>) -> Result<(), Box<dyn Error>> {
    let mut server_input = [0_u8; 200];
    loop {
        let _ = stream.read(&mut server_input);
        match from_utf8(&server_input) {
            Ok(content) => {
                if content.trim_end_matches("\0") == expected {
                    break
                }
            },
            Err(_) => {
                println!("[CLIENT] unexpected message: {:?}", server_input);
            }
        }
    }
    stream.write_all(if data.is_empty() { &[0] } else { &data })?;
    stream.flush()?;
    Ok(())
}

fn update_move_toml_with_address(challenge_addr: &str) -> Result<(), Box<dyn Error>> {
    // Update dependency/Move.toml
    let dependency_toml_path = "./dependency/Move.toml";
    let dependency_content = format!(
r#"[package]
name = "challenge"
version = "0.0.1"
edition = "2024.beta"

[dependencies]
Sui = {{ git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "mainnet-v1.30.1" }}

[addresses]
admin = "0xfccc9a421bbb13c1a66a1aa98f0ad75029ede94857779c6915b44f94068b921e"
challenge = "0x{}"
"#, challenge_addr);
    fs::write(dependency_toml_path, dependency_content)?;

    // Update solve/Move.toml
    let solve_toml_path = "./solve/Move.toml";
    let solve_content = format!(
r#"[package]
name = "solution"
version = "0.0.1"
edition = "2024.beta"

[dependencies]
Sui = {{ git = "https://github.com/MystenLabs/sui.git", subdir = "crates/sui-framework/packages/sui-framework", rev = "mainnet-v1.30.1" }}

[dependencies.challenge]
local = '../dependency'

[addresses]
solution = "0x0"
challenge = "0x{}"
"#, challenge_addr);
    fs::write(solve_toml_path, solve_content)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "31337".to_string());

    match TcpStream::connect(format!("{}:{}", host, port)) {
        Ok(mut stream) => {
            println!("  - Connected!");

            // First, get the challenge address from server
            let mut return_data = [0_u8; 200];
            
            // Read the challenge address message
            match stream.read(&mut return_data) {
                Ok(_) => {
                    let response = from_utf8(&return_data).unwrap().trim_end_matches("\0");
                    println!("  - Connection Output: '{}'", response);
                    
                    // Parse challenge address from "[SERVER] Challenge modules published at: <address>"
                    if let Some(addr_start) = response.find("Challenge modules published at: ") {
                        let addr_part = &response[addr_start + 32..];
                        let challenge_addr = addr_part.trim();
                        println!("  - Extracted challenge address: {}", challenge_addr);
                        
                        // Update Move.toml files with the correct address
                        update_move_toml_with_address(challenge_addr)?;
                        println!("  - Updated Move.toml files with challenge address");
                        
                        // Now rebuild the solution with correct address
                        std::process::Command::new("sui")
                            .args(&["move", "build"])
                            .current_dir("./solve")
                            .status()?;
                        println!("  - Rebuilt solution with correct challenge address");
                    }
                },
                Err(e) => { 
                    println!("  - Failed to receive challenge address: {}", e);
                    return Err(e.into());
                }
            }

            let mod_data : Vec<u8> =
                fs::read("./solve/build/solution/bytecode_modules/solution.mv").unwrap();
            println!("  - Loaded solution!");

            let _ = send_after(&mut stream, "[SERVER] solution:", mod_data);
            println!("  - Sent solution!");

            let params = prepare_params(PARAMS_LIST.to_vec());
            let _ = send_after(&mut stream, "[SERVER] arguments:", params.to_vec());
            println!("  - Sent parameters list!");

            // Read solution address
            let mut return_data = [0_u8; 200];
            match stream.read(&mut return_data) {
                Ok(_) => {
                    println!("  - Connection Output: '{}'", from_utf8(&return_data).unwrap());
                    let mut flag = [0_u8; 200]; 
                    match stream.read(&mut flag) {
                        Ok(_) => {
                            println!("  - Connection Output: '{}'", from_utf8(&flag).unwrap());
                        },
                        Err(e) => { println!("  - Failed to receive data: {}", e); }
                    }
                },
                Err(e) => { println!("  - Failed to receive data: {}", e); }
            }
        },
        Err(e) => { println!("  - Failed to connect: {}", e); }
    }
    println!("  - Terminated.");

    Ok(())
}