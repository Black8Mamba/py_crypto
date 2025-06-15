import argparse
import logging
import os

import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

DEFAULT_PRIVATE_KEY = 'private_key.pem'
DEFAULT_PUBLIC_KEY = 'public_key.pem'
DEFAULT_AES_KEY = 'aes_key.txt'

#--pub-key public_key.pem --verify test_file.txt --signature signature.bin
#--gen-aes-key --aes-key 'aes_key.txt'


def parse_cli_arguments():
    ''' Parses the command line arguments.
    '''
    parser = argparse.ArgumentParser(description='Create a new blob image or update an existing one based on json coniguration file.')
    parser.add_argument('--gen-rsa-key', action='store_true', help='Generate RSA2048 public/private key pair')
    parser.add_argument('--gen-aes-key', action='store_true', help='Generate a random AES256 key')
    parser.add_argument('--priv-key', type=str, default=DEFAULT_PRIVATE_KEY, help='Private key output file')
    parser.add_argument('--pub-key', type=str, default=DEFAULT_PUBLIC_KEY, help='Public key output file')
    parser.add_argument('--aes-key', type=str, default=DEFAULT_AES_KEY, help='AES key output file')
    parser.add_argument('--sign', type=str, help='Sign a file using RSA-PSS')
    parser.add_argument('--verify', type=str, help='Verify a signature using RSA-PSS')
    parser.add_argument('--signature', type=str, help='Signature file for verification')
    return parser.parse_args()

def generate_rsa2048_keypair(private_key_path, public_key_path):
    """Generate RSA2048 key pair and save to files."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Save private key
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    # Save public key
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print(f"RSA2048 key pair generated:\n  Private key: {private_key_path}\n  Public key: {public_key_path}")

def sign_file_with_pss(private_key_path, file_path, signature_path):
    """Sign a file using RSA-PSS."""
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    with open(file_path, "rb") as f:
        data = f.read()
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    with open(signature_path, "wb") as sig_file:
        sig_file.write(signature)
    print(f"File signed. Signature saved to {signature_path}")

def verify_file_with_pss(public_key_path, file_path, signature_path):
    """Verify a file's signature using RSA-PSS."""
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    with open(file_path, "rb") as f:
        data = f.read()
    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid!")
    except Exception as e:
        print("Signature verification failed:", e)

def generate_aes256_key(filepath):
    """Generate a random 256-bit (32 bytes) AES key and save as hex to file."""
    key = secrets.token_bytes(32)
    with open(filepath, "w") as f:
        f.write(key.hex())
    print("AES256 key (hex):", key.hex())
    print(f"AES256 key saved to {filepath}")

def main():
    args = parse_cli_arguments()
    if args.gen_rsa_key:
        print("start gen rsa key")
        generate_rsa2048_keypair(args.priv_key, args.pub_key)
    elif args.sign:
        print("start sign file")
        sign_file_with_pss(args.priv_key, args.sign, args.signature or "signature.bin")
    elif args.verify:
        print("start verify file")
        verify_file_with_pss(args.pub_key, args.verify, args.signature)
    if args.gen_aes_key and args.aes_key:
        print("start gen aes key")
        generate_aes256_key(args.aes_key)
    else:
        print("hello crypto,nothing todo!")


if __name__ == "__main__":
    main()