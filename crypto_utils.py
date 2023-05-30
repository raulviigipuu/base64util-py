import os
import base64
import hashlib
import nacl.secret
import nacl.utils


def encrypt(plaintext: str, password: str) -> str:
    # Derive a key from the password
    salt = os.urandom(16)
    key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=nacl.secret.SecretBox.KEY_SIZE,
    )

    # Encrypt the plaintext using the key
    box = nacl.secret.SecretBox(key)
    ciphertext = box.encrypt(plaintext.encode())

    # Concatenate the salt and ciphertext
    encrypted_data = salt + ciphertext
    print("Salt:", salt)
    print("Ciphertext:", ciphertext)
    print("Encrypted data:", encrypted_data)

    return base64.b64encode(encrypted_data).decode("utf-8")


def decrypt(ciphertext: str, password: str) -> str:
    # Decode the input from base64
    decoded = base64.b64decode(ciphertext)
    print("Decoded:", decoded)

    # Extract the salt and ciphertext from the input
    salt = decoded[:16]
    ciphertext = decoded[16:]
    print("Salt:", salt)
    print("Ciphertext:", ciphertext)

    # Derive a key from the password
    key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=nacl.secret.SecretBox.KEY_SIZE,
    )
    print("Key:", key)

    # Decrypt the ciphertext using the key
    box = nacl.secret.SecretBox(key)
    try:
        plaintext = box.decrypt(ciphertext)
    except Exception as e:
        print("Error during decryption:", e)
        raise

    return plaintext.decode("utf-8")


# Example usage
# plaintext = "Hello, world!"
# password = "my password"

# ciphertext = encrypt(plaintext, password)
# print(f"Ciphertext: {ciphertext}")
# decrypted = decrypt(ciphertext, password)

# print(f"Decrypted: {decrypted}")
