use rand::thread_rng;
use rand::Rng;
use std::str;
use std::fs::{self, File, metadata};
use std::io::{self, Read, Write};

use aes::{Aes128, Aes192, Aes256};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

// Define types for different AES key sizes
type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes192Cbc = Cbc<Aes192, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Function to read input from user
fn input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).expect("Failed to read line");
    buffer.trim().to_string()
}

// Function to get a random key of specified length (in bytes)
fn get_random_key(length: usize) -> Vec<u8> {
    let mut key = vec![0u8; length];
    thread_rng().try_fill(&mut key[..]).expect("Failed to generate key");
    key
}

// Function to read the content of a file
fn read_file(file_path: &str) -> Vec<u8> {
    // Check if the path is a file
    let meta = metadata(file_path).expect("Failed to retrieve metadata");
    if meta.is_dir() {
        panic!("The path provided is a directory, not a file.");
    }

    let mut file = File::open(file_path).expect("Failed to open file");
    let mut content = Vec::new();
    file.read_to_end(&mut content).expect("Failed to read file");
    content
}

// Function to write encrypted content into a file
fn write_file(file_path: &str, content: &[u8]) {
    let mut file = File::create(file_path).expect("Failed to create file");
    file.write_all(content).expect("Failed to write to file");
}

// Function to encrypt data using AES-128, AES-192, or AES-256
fn encrypt_data(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; data.len() + 16]; // Padding buffer
    buffer[..data.len()].copy_from_slice(data);

    match key.len() {
        16 => {
            let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
            cipher.encrypt(&mut buffer, data.len()).unwrap().to_vec()
        },
        24 => {
            let cipher = Aes192Cbc::new_from_slices(key, iv).unwrap();
            cipher.encrypt(&mut buffer, data.len()).unwrap().to_vec()
        },
        32 => {
            let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
            cipher.encrypt(&mut buffer, data.len()).unwrap().to_vec()
        },
        _ => panic!("Invalid key size!"),
    }
}

// Function to decrypt data using AES-128, AES-192, or AES-256
fn decrypt_data(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut buffer = encrypted_data.to_vec();

    match key.len() {
        16 => {
            let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
            cipher.decrypt(&mut buffer).unwrap().to_vec()
        },
        24 => {
            let cipher = Aes192Cbc::new_from_slices(key, iv).unwrap();
            cipher.decrypt(&mut buffer).unwrap().to_vec()
        },
        32 => {
            let cipher = Aes256Cbc::new_from_slices(key, iv).unwrap();
            cipher.decrypt(&mut buffer).unwrap().to_vec()
        },
        _ => panic!("Invalid key size!"),
    }
}

fn main() {
    // Step 1: Let user choose encryption strength (128, 192, or 256 bits)
    let key_size_choice = input(
        "Choose encryption key size (1: 128 bits, 2: 192 bits, 3: 256 bits): ",
    );
    let key_size = match key_size_choice.as_str() {
        "1" => 16, // 128 bits = 16 bytes
        "2" => 24, // 192 bits = 24 bytes
        "3" => 32, // 256 bits = 32 bytes
        _ => {
            println!("Invalid choice, defaulting to 128 bits.");
            16
        }
    };

    // Step 2: Generate the key based on user's choice
    let key = get_random_key(key_size);
    println!(
        "Generated a random key of size {} bits: {:?}",
        key_size * 8,
        hex::encode(&key)
    );

    // Step 3: Ask the user for a secret phrase to use as IV
    let mut iv = input("Enter a secret phrase for IV (16, 24, or 32 characters): ");

    // Ensure the IV is 16, 24, or 32 bytes long
    while iv.len() != 16 && iv.len() != 24 && iv.len() != 32 {
        iv = input("IV must be 16, 24, or 32 characters long. Please try again: ");
    }

    let iv = iv.as_bytes();

    // Step 4: Get the file path to encrypt from the user
    let file_path = input("Enter the file path to encrypt: ");
    let file_content = read_file(&file_path);
    println!("File content: {:?}", String::from_utf8_lossy(&file_content));

    // Step 5: Encrypt the file content
    let encrypted_data = encrypt_data(&file_content, &key, iv);

    // Save encrypted content into a new file
    let encrypted_file_path = format!("{}.enc", file_path);
    write_file(&encrypted_file_path, &encrypted_data);
    println!("File encrypted and saved as: {}", encrypted_file_path);

    // Step 6: Decrypt the content to verify
    let decrypted_data = decrypt_data(&encrypted_data, &key, iv);
    println!("\nDecrypted content: {}", String::from_utf8_lossy(&decrypted_data));

    // Step 7: Save decrypted content into a new file (optional)
    let decrypted_file_path = format!("{}_decrypted.txt", file_path);
    write_file(&decrypted_file_path, &decrypted_data);
    println!("Decrypted file saved as: {}", decrypted_file_path);
}

