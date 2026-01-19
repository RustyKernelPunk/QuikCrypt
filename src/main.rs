use clap::Parser;
use std::io::{self, Read, Write, stdin, stdout};
use argon2::{
    Argon2
};
use std::fs;
use std::path::Path;

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
fn main() -> Result<(), Box<dyn std::error::Error>>{
    let args = Args::parse();
    let path = "~/.config/quikcrypt";
    if Path::new(path).exists(){
        println!("~/.config/quikcrypt exists, moving on...");
    } else{
        println!("Creating ~/.config/quikcrypt directory for encrypted storage...");
        let file_path = Path::new(path);
        fs::create_dir(file_path)?;
    }
    if args.create_file{
        let mut input = Vec::new();
        std::io::stdin().read_to_end(&mut input);
        println!("Enter a secure encryption password:");
        let mut password = String::new();
        stdin().read_line(&mut password)?;
        let password = password.as_bytes();
        let mut key = [0u8; 32];
        let mut salt = [0u8; 16];
        OsRng.try_fill_bytes(&mut salt).unwrap();
        let secure_key = Argon2::default().hash_password_into(password, &salt[..], &mut key).expect("failed to hash password.");
        println!("Creating file at {}", args.filepath);
    }
    if args.decrypt{
        println!("Decrypting file at {}", args.filepath);
    }
    Ok(())
}
