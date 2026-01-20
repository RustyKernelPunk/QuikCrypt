use clap::Parser;
use std::io::{Read, Write};
use argon2::{
    Argon2
};
use std::fs::File;
use std::fs;
use std::path::{PathBuf};
use zeroize::Zeroize;
use chacha20poly1305::{
    aead::Aead,
    ChaCha20Poly1305, 
    Nonce,
    KeyInit,
};
use rpassword::read_password;
use color_eyre::eyre::{Result, bail};

use rand_core::{OsRng, TryRngCore};
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Command to create file, prompts for password to encrypt with
    #[arg(short, long)]
    create_file: bool,
    /// Command to decrypt file, prompts for password & displays file contents
    #[arg(short, long)]
    decrypt: bool,
    /// Specifies filepath to create/decrypt
    #[arg(short, long, default_value = "note.enc")]
    filepath: String,
  }
const SALT_LENGTH: usize = 16;
const NONCE: usize = 12;
fn main() -> Result<()>{
    color_eyre::install()?;

    let args = Args::parse();
    let mut path: PathBuf = dirs::home_dir().expect("Failed to get home directory.");
    path.push(".config");
    path.push("quikcrypt");
    if path.exists(){
        println!("~/.config/quikcrypt exists, moving on...");
    } else{
        println!("Creating ~/.config/quikcrypt directory for encrypted storage...");
        fs::create_dir_all(&path)?;
    }
    if args.create_file{
        let mut key = [0u8; 32];
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];

        let mut plaintext = Vec::new();
        std::io::stdin().read_to_end(&mut plaintext)?;

        println!("Enter a secure encryption password: ");
        let password = read_password()?;
        let password = password.as_bytes();

        if password.len() < 8 {
            bail!("Password too short and insecure! Must be longer!");
        }
        OsRng.try_fill_bytes(&mut salt).unwrap();
        Argon2::default().hash_password_into(password, &salt[..], &mut key).expect("Couldn't hash password!");        
        OsRng.try_fill_bytes(&mut nonce_bytes).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = ChaCha20Poly1305::new(&key.into());
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("Failed to encrypt file.");
        let mut file_path = path.clone();
        file_path.push(&args.filepath);
        let mut file =  File::create(&file_path)?;
        file.write_all(&salt)?;
        file.write_all(&nonce_bytes)?;
        file.write_all(&ciphertext)?;

        println!("Creating file at ~/.config/quikcrypt/{}", args.filepath);

        plaintext.zeroize();
        key.zeroize();
        let mut password_bytes = password.to_vec();
        password_bytes.zeroize();
    }
    if args.decrypt{
        println!("Enter the file's password: ");
        let password = read_password()?;
        let password = password.as_bytes();

        path.push(args.filepath);

        let mut encrypted_file = File::open(path)?;
        let mut buf = Vec::new();
        encrypted_file.read_to_end(&mut buf)?;
        
        let salt = buf[0..SALT_LENGTH].to_vec();
        let nonce = buf[SALT_LENGTH..SALT_LENGTH + NONCE].to_vec();
        let ciphertext = buf[SALT_LENGTH + NONCE..].to_vec();

        println!("Decrypting file...");
    }
    Ok(())
}

