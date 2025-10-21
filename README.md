# Chiffrement de fichiers

## Setup

```bash
cargo build
```

## Partie 1 : Chiffrement d'un seul fichier

### usage :

Chiffrement :

```bash
./target/release/chiffreur encrypt fichier_clair -o fichier_chiffre
```

Déchiffrement :

```bash
./target/release/chiffreur decrypt fichier_chiffre -o fichier_clair
```

### Note :

Je n'ai pas utilisé la lib [rand](https://crates.io/crates/rand) (pour la génération d'aléa).

En effet, elle n'était pas utile pour la dérivation de clé car on devait pouvoir retrouver la même dérivation pour un même mot de passe ; et la lib [aes_gcm](https://crates.io/crates/aes_gcm) (pour le chiffrement symétrique) proposait une autre façon de gérer l'aléa (aes_gcm::aead::OsRng).

## Partie 2 : Chiffrement de plusieurs fichiers
