import argparse
import logging
import os

import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
# from cryptography.hazmat.primitives import serialization, hashes

DEFAULT_PRIVATE_KEY = 'private_key.pem'
DEFAULT_PUBLIC_KEY = 'public_key.pem'
DEFAULT_AES_KEY = 'aes_key.txt'

#--pub-key public_key.pem --verify test_file.txt --signature signature.bin
#--gen_aes_key --aes-key aes_key.txt
#--aes_encrypt --aes_key aes_key.txt --in_file test_file.txt --out_file test_file_enc.txt
#--aes_encrypt --aes_key aes_key.txt --in_file MIMXRT1052_Project_Demo.bin --out_file MIMXRT1052_Project_Demo_enc.bin
#--aes_decrypt --aes_key aes_key.txt --in_file test_file_enc.txt --out_file test_file_dec.txt
#--aes_decrypt --aes_key aes_key.txt --in_file MIMXRT1052_Project_Demo_enc.bin --out_file MIMXRT1052_Project_Demo_dec.bin
#--rsa-pub-encrypt --pub_key public_key.pem --in_file aes_key.txt --out_file aes_key_rsa_enc.txt
#--rsa_priv_decrypt --priv_key private_key.pem --in_file aes_key_rsa_enc.txt --out_file aes_key_rsa_dec.txt

#--append_sign --in_file MIMXRT1052_Project_Demo.bin --out_file MIMXRT1052_Project_Demo_sign.bin --signature signature.bin

#srec_cat.exe MIMXRT1052_Project_Demo.bin -binary -offset 0x60000000  -output MIMXRT1052_Project_Demo_new.s19 -Motorola

def parse_cli_arguments():
    ''' Parses the command line arguments.
    '''
    parser = argparse.ArgumentParser(description='Create a new blob image or update an existing one based on json coniguration file.')
    parser.add_argument('--gen_rsa_key', action='store_true', help='Generate RSA2048 public/private key pair')
    parser.add_argument('--gen_aes_key', action='store_true', help='Generate a random AES256 key')
    parser.add_argument('--priv_key', type=str, default=DEFAULT_PRIVATE_KEY, help='Private key output file')
    parser.add_argument('--pub_key', type=str, default=DEFAULT_PUBLIC_KEY, help='Public key output file')
    parser.add_argument('--aes_key', type=str, default=DEFAULT_AES_KEY, help='AES key output file')
    parser.add_argument('--sign', type=str, help='Sign a file using RSA-PSS')
    parser.add_argument('--verify', type=str, help='Verify a signature using RSA-PSS')
    parser.add_argument('--signature', type=str, help='Signature file for verification/append')
    parser.add_argument('--aes_encrypt', action='store_true', help='Encrypt a file with AES256')
    parser.add_argument('--aes_decrypt', action='store_true', help='Decrypt a file with AES256')
    parser.add_argument('--in_file', type=str, help='Input file for AES encryption/decryption')
    parser.add_argument('--out_file', type=str, help='Output file for AES encryption/decryption')
    parser.add_argument('--rsa_priv_encrypt',action='store_true', help='Encrypt a file with RSA-PSS private key')
    parser.add_argument('--rsa_pub_encrypt', action='store_true', help='Encrypt a file with RSA-PSS pubilc key')
    parser.add_argument('--rsa_priv_decrypt', action='store_true', help='Output file for decrypted AES key (hex)')
    parser.add_argument('--rsa_pub_decrypt', action='store_true', help='Output file for decrypted AES key (hex)')
    parser.add_argument('--input_type', type=str, help='input file type, binary/hex')
    parser.add_argument('--append_sign', action='store_true', help='append signature data to bin file')

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

def append_rsapss_signature(bin_file, out_bin_file, signature):
    with open(bin_file, "rb") as f:
        data = f.read()

    with open(signature, "rb") as s:
        sign = s.read()

    align = 0x100
    pad_len = (align - (len(data) % align)) % align
    # 追加填充和签名到bin文件末尾
    with open(out_bin_file, "wb") as f:
        f.write(data)
        if pad_len:
            f.write(b'\xFF' * pad_len)
        f.write(sign)
    print(f"Signature (aligned to 0x100) appended to {out_bin_file}")

def generate_aes256_key(filepath):
    """Generate a random 256-bit (32 bytes) AES key and save as hex to file."""
    key = secrets.token_bytes(32)
    with open(filepath, "w") as f:
        f.write(key.hex())
    print("AES256 key (hex):", key.hex())
    print(f"AES256 key saved to {filepath}")

def read_aes_key_from_file(filepath):
    """Read AES256 key (hex) from a text file."""
    with open(filepath, "r") as f:
        key_hex = f.read().strip()
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        raise ValueError("AES256 key must be 32 bytes (64 hex chars)")
    return key

def aes256_encrypt_file(input_path, key_file, output_path):
    """Encrypt a file using AES256-CBC, key from file."""
    key = read_aes_key_from_file(key_file)
    import secrets
    iv = secrets.token_bytes(16)
    print("random iv (hex):", iv.hex())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()

    with open(input_path, "rb") as f:
        data = f.read()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_path, "wb") as out:
        out.write(iv + ciphertext)
    print(f"File encrypted with AES256. Output: {output_path}")

def aes256_decrypt_file(input_path, key_file, output_path):
    """Decrypt a file using AES256-CBC, key from file."""
    key = read_aes_key_from_file(key_file)
    with open(input_path, "rb") as f:
        iv = f.read(16)
        print("iv (hex):", iv.hex())
        ciphertext = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    with open(output_path, "wb") as out:
        out.write(data)
    print(f"File decrypted with AES256. Output: {output_path}")

def rsa_pss_private_encrypt(input_path, priv_key_file, output_path):
    """Encrypt AES256 key with RSA private key using PSS padding."""
    # 读取AES密钥
    with open(input_path, "r") as f:
        aes_key_hex = f.read().strip()
        print("aes_key_hex (hex):", aes_key_hex)
    aes_key = bytes.fromhex(aes_key_hex)
    # 读取RSA私钥
    with open(priv_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    # 用私钥加密AES密钥（实际上通常用公钥加密，这里按你的需求用私钥加密）
    encrypted = private_key.sign(
        aes_key,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    with open(output_path, "wb") as out:
        out.write(encrypted)
    print(f"AES256 key encrypted with RSA private key (PSS). Output: {output_path}")

def rsa_pss_public_encrypt(input_path, pub_key_file, output_path):
    """Encrypt AES256 key with RSA public key using OAEP padding."""
    # 读取AES密钥
    with open(input_path, "r") as f:
        aes_key_hex = f.read().strip()
        print("aes_key_hex (hex):", aes_key_hex)
    aes_key = bytes.fromhex(aes_key_hex)
    # 读取RSA公钥
    with open(pub_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    # 用公钥加密AES密钥（推荐用OAEP而不是PSS用于加密）
    encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_path, "wb") as out:
        out.write(encrypted)
    print(f"AES256 key encrypted with RSA public key (OAEP). Output: {output_path}")

def rsa_private_decrypt(input_path, priv_key_file, output_path):
    """Decrypt AES256 key with RSA private key using OAEP padding."""
    with open(input_path, "rb") as f:
        encrypted = f.read()
    with open(priv_key_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    aes_key = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(output_path, "w") as out:
        out.write(aes_key.hex())
    print(f"AES256 key decrypted and saved to {output_path}")

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
    elif args.gen_aes_key and args.aes_key:
        print("start gen aes key")
        generate_aes256_key(args.aes_key)
    elif args.aes_encrypt and args.aes_key and args.out_file and args.in_file:
        print("start aes256 cbc encrypt")
        aes256_encrypt_file(args.in_file, args.aes_key, args.out_file)
    elif args.aes_decrypt and args.aes_key and args.out_file and args.in_file:
        print("start aes256 cbc decrypt")
        aes256_decrypt_file(args.in_file, args.aes_key, args.out_file)
    elif args.rsa_pub_encrypt and args.pub_key and args.in_file and args.out_file:
        print("start rsa pub encrypt")
        rsa_pss_public_encrypt(args.in_file, args.pub_key, args.out_file)
    elif args.rsa_priv_decrypt and args.priv_key and args.in_file and args.out_file:
        print("start rsa priv decrypt")
        rsa_private_decrypt(args.in_file, args.priv_key, args.out_file)
    elif args.append_sign and args.in_file and args.out_file and args.signature:
        append_rsapss_signature(args.in_file, args.out_file, args.signature)
    else:
        print("hello crypto,nothing todo!")

if __name__ == "__main__":
    main()