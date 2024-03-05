from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets
import requests
import argparse
import os, sys
from dotenv import load_dotenv
load_dotenv()
parser=argparse.ArgumentParser()

parser.add_argument("-cipher", help="Specify path to store the cipher")
parser.add_argument("-public", help="Specify path to read the public key")
parser.add_argument("-text", help="Specify text to encrypt (if not file)")
parser.add_argument("-file", help="Specify file to encrypt (if not text)")
parser.add_argument("-store_encrypted", help="Where to store the encrypted text")

args=parser.parse_args()

url = 'https://www.exequantum.com/api/kc'

if os.environ.get('ENVIRONMENT') == 'development':
    url = 'http://localhost:8000/api/kc'

def _encapsulate_key(pk):
    """
    Call the API endpoint to encapsulate the key. 
    This generates a cipher and a shared key.
    """
    api_url = url + "/encapsulate_key?pk=" + pk + "&auth_token=" + os.environ.get('AUTH_TOKEN')
    response = requests.get(api_url)
    keys = response.json()
    
    return bytes.fromhex(keys['cipher']), bytes.fromhex(keys['shared_key'])

def _generate_shared_key_cipher():
    """
    Use the public key to generate the cipher and shared key.
    Includes calling the API endpoint to do so.
    """
    public_path = args.public
    p_key =  open(public_path, "r").read()
    cipher, key = _encapsulate_key(p_key)
    _store_cipher(cipher)    
    return key

def _store_cipher(cipher):    
    cipher_path = args.cipher
    os.makedirs(os.path.dirname(cipher_path), exist_ok=True)
    # Where the cipher is stored is subject to change based on use case.
    # The cipher is NOT sensitive information and therefore won't need extra security when stored.
    f = open(cipher_path, "w")
    f.write(cipher.hex())
    f.close()
    print('Stored cipher successfully')

def _encrypt_text(text, shared_key): 
    # Use AES and the shared secret to encrypt data.
    iv = secrets.token_bytes(16)

    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(text.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    return (iv + ciphertext).hex()

def _store_encrypted_text(enc_text, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    f = open(path, "w")
    f.write(enc_text)
    f.close()
    print('Encrypted text stored successfully')

def _encrypt_file(file, shared_key):
    plain_file = open(file, "r").read()
    encrypted_content = _encrypt_text(plain_file, shared_key)

    return encrypted_content

def encrypt():
    # Putting it all together
    shared_key = _generate_shared_key_cipher()

    text = args.text
    file = args.file
    if text != None:
        encrypted_text = _encrypt_text(text, shared_key)
    if file != None:
        encrypted_text = _encrypt_file(file, shared_key)

    text_path = args.store_encrypted
    _store_encrypted_text(encrypted_text, text_path)

    return encrypted_text

if __name__ == "__main__":
    # Can only encrypt a text or a file, not both
    if(args.text != None and args.file != None):
        sys.exit('Error: you can only encrypt a file or text, not both')
    if args.store_encrypted == None or args.public == None or args.cipher == None or args.text == None and args.file == None:
        sys.exit('Error: please make sure to specify path for cipher (-cipher), public key (-public_path), where to store the encrypted text (-store_encrypted) and a file or text to encrypt')
    message = encrypt()  
