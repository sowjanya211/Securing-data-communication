import os
!pip install reedsolo
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.hashes import SHA256
import reedsolo
import time

def add_reed_solomon_error_correction(data):
    rs = reedsolo.RSCodec(10)  # Initialize RSCodec with the desired number of error correction bytes
    encoded_data = rs.encode(data.encode('utf-8'))
    return encoded_data

def remove_reed_solomon_error_correction(data):
    rs = reedsolo.RSCodec(10)
    decoded_data = rs.decode(data)[0]
    return decoded_data.decode('utf-8')

def hybrid_encrypt(plaintext, public_key):
    # Pad the plaintext
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padded_plaintext = pkcs7_padder.update(plaintext) + pkcs7_padder.finalize()

    # Generate new random AES-256 key
    key = os.urandom(256 // 8)

    # Generate new random 128 IV required for CBC mode
    iv = os.urandom(128 // 8)

    # AES CBC Cipher
    aes_cbc_cipher = Cipher(AES(key), CBC(iv))

    # Encrypt padded plaintext
    ciphertext = aes_cbc_cipher.encryptor().update(padded_plaintext)

    # Encrypt AES key
    oaep_padding = asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    cipherkey = public_key.encrypt(key, oaep_padding)

    return {'iv': iv, 'ciphertext': ciphertext}, cipherkey

def hybrid_decrypt(ciphertext, cipherkey, private_key):
    # Decrypt AES key
    oaep_padding = asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    recovered_key = private_key.decrypt(cipherkey, oaep_padding)

    # Decrypt padded plaintext
    aes_cbc_cipher = Cipher(AES(recovered_key), CBC(ciphertext['iv']))
    recovered_padded_plaintext = aes_cbc_cipher.decryptor().update(ciphertext['ciphertext'])

    # Remove padding
    pkcs7_unpadder = padding.PKCS7(AES.block_size).unpadder()
    recovered_plaintext = pkcs7_unpadder.update(recovered_padded_plaintext) + pkcs7_unpadder.finalize()

    return recovered_plaintext

# Recipient's private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Public key to make available to sender
public_key = private_key.public_key()

# Plaintext to send hybrid encrypted
plaintext = 'MY name is Sowjanya !!!'

# Add Reed-Solomon error correction
encoded_plaintext = add_reed_solomon_error_correction(plaintext)

# Hybrid encrypt encoded plaintext
start_time = time.time()
ciphertext, cipherkey = hybrid_encrypt(encoded_plaintext, public_key)
encryption_time = time.time() - start_time

# Hybrid decrypt ciphertext
start_time = time.time()
recovered_encoded_plaintext = hybrid_decrypt(ciphertext, cipherkey, private_key)
decryption_time = time.time() - start_time

# Remove Reed-Solomon error correction
recovered_plaintext = remove_reed_solomon_error_correction(recovered_encoded_plaintext)

# Calculate BER and FER
num_bits = len(encoded_plaintext) * 8
num_errors = sum(a != b for a, b in zip(encoded_plaintext, recovered_encoded_plaintext))
ber = num_errors / num_bits
fer = 1 if num_errors > 0 else 0

# Calculate overhead
original_size = len(plaintext.encode('utf-8'))
encoded_size = len(encoded_plaintext)
overhead = encoded_size - original_size

print("\nInput Plaintext:", plaintext)
print("Received Plaintext:", recovered_plaintext)