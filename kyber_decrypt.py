from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import argparse
import os, sys
import requests
from dotenv import load_dotenv
load_dotenv()
parser=argparse.ArgumentParser()

parser.add_argument("-cipher", help="Specify path to read the padding cipher")
parser.add_argument("-private", help="Specify path to read the private key")
parser.add_argument("-text", help="Specify text to decrypt (if not file)")
parser.add_argument("-file", help="Specify file to decrypt (if not text)")
parser.add_argument("-store_decrypted", help="Where to store the decrypted text")

args=parser.parse_args()

url = 'https://www.exequantum.com/api/kc'

if os.environ.get('ENVIRONMENT') == 'development':
    url = 'http://localhost:8000/api/kc'

def _decapsulate_key(cipher, s_key):
    api_url = url + "/decapsulate_key?sk=" + s_key + "&cipher=" + cipher + "&auth_token=" + os.environ.get('AUTH_TOKEN')
    response = requests.get(api_url)
    keys = response.json()

    return bytes.fromhex(keys['shared_key'])

def _generate_secret_from_private(cipher, s_key):
    key = _decapsulate_key(cipher, s_key)
    
    return key

def _read_cipher():
    cipher_path = args.cipher
    return open(cipher_path, "r").read()

def _read_secret():
    private_path = args.private
    return open(private_path, "r").read()

def _decrypt_text(ciphertext):
    iv = ciphertext[:16]
    cipher = _read_cipher()
    secret_key = _read_secret()
    shared_key = _generate_secret_from_private(cipher, secret_key)

    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_message = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    return unpadded_message.decode()

def _decrypt_file(ciphertext_path):
    text = bytes.fromhex(open(ciphertext_path, "r").read())
   
    return _decrypt_text(text)
    
def _store_decrypted_text(text, text_path):
    os.makedirs(os.path.dirname(text_path), exist_ok=True)
    f = open(text_path, "w")
    f.write(text)
    f.close()
    print('Encrypted text stored successfully')

def decrypt(): 
    text = args.text
    file = args.file

    text_path = args.store_decrypted

    if text != None:
        _store_decrypted_text(_decrypt_text(text), text_path) 
    if file != None:
        _store_decrypted_text(_decrypt_file(file), text_path) 

    return 'Success'

if __name__ == "__main__":
    if(args.text != None and args.file != None):
        sys.exit('Error: you can only encrypt a file or text, not both')
    if args.store_decrypted == None or args.cipher == None or args.text == None and args.file == None:
        sys.exit('Error: please make sure to specify path for cipher (-cipher), public key (-public_path), where to store the decrypted text (-store_decrypted) and a file or text to decrypt')
    decrypt()  
