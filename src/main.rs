use clap::{Parser, Subcommand};
use argon2::Argon2;
use std::fs::File;
use std::io::{Read, Write};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use generic_array::GenericArray;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        /// fichier à chiffrer
        input: String,
        /// fichiers de sortie (chiffré)
        #[arg(short,long)]
        output: String,
    },
    Decrypt {
        /// fichier à déchiffrer
        input: String,
        /// fichier de sortie (déchiffré)
        #[arg(short,long)]
        output: String,
    },
}

fn derive_key() -> [u8; 32] {
    // PASSWORD:
    let password = rpassword::prompt_password("Entrez le mot de passe : ").expect("Erreur de lecture du mot de passe");
    let password: &[u8] = password.as_bytes(); // on convertit en tab de bytes
    if password.len() > 32 { // verif: password ne doit pas excéder 32 char.
        panic!("Le mot de passe ne doit pas dépasser 32 caractères.");
    }
    // SALT: la même key doit être retrouvée à partir du même password
    // cet algo doit donc être déterministe => on garde le même salt
    let salt = b"example salt";
    // rand::rng().fill_bytes(&mut salt);
    // KEY:
    let mut output_key_material = [0u8; 32];
    let _ = Argon2::default().hash_password_into(password, salt, &mut output_key_material);
    output_key_material
}

fn encrypt_file(input: &str, output: &str, key: [u8; 32]) -> () {
    // lecture du fichier d'entrée en clair :
    let mut file = File::open(input).expect("Impossible d'ouvrir le fichier d'entrée");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Erreur de lecture du fichier");

    // docu aes_gcm :
    let key: &Key<Aes256Gcm> = &key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, data.as_ref()).expect("Erreur lors du chiffrement");

    // écriture chiffrée dans le fichier de sortie
    let mut out_file = File::create(output).expect("Impossible de créer le fichier de sortie");
    out_file.write_all(&nonce).unwrap(); // on stocke le nonce en début de fichier
    out_file.write_all(&ciphertext).unwrap();
    println!("✅ Fichier chiffré avec succès !");
}

fn decrypt_file(input: &str, output: &str, key: [u8; 32]) -> () {
    // lecture du fichier chiffré :
    let mut file = File::open(input).expect("Impossible d'ouvrir le fichier d'entrée");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Erreur de lecture du fichier");

    // docu aes_gcm :
    let key: &Key<Aes256Gcm> = &key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes = &data[0..12];
    let nonce = GenericArray::from_slice(nonce_bytes);
    let ciphertext = &data[12..data.len()];

    // pattern matching pour chopper le "Vec<u8>" dans le Result<...>
    let decrypted_data = match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Erreur de décryptage: {:?}", e);
            return;
        }
    };

    // écriture en clair dans le fichier de sortie
    let mut out_file = File::create(output).expect("Impossible de créer le fichier de sortie");
    out_file.write_all(&decrypted_data).unwrap();
    println!("✅ Fichier déchiffré avec succès !");
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Encrypt { input, output } => {
            println!("🔒 Chiffrement de `{}` -> `{}`", input, output);
            let key = derive_key();
            encrypt_file(&input, &output, key);
        }
        Commands::Decrypt { input, output } => {
            println!("🔓 Déchiffrement de `{}` -> `{}`", input, output);
            let key = derive_key();
            decrypt_file(&input, &output, key);
        }
    }
}
