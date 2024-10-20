import argparse
import os, sys
import requests
from dotenv import load_dotenv

load_dotenv()
parser=argparse.ArgumentParser()

parser.add_argument("-cipher", help="Specify path to read the padding cipher")
parser.add_argument("-secret", help="Specify path to read the secret key")
parser.add_argument("-text", help="Specify text to decrypt (if not file)")
parser.add_argument("-file", help="Specify file to decrypt (if not text)")
parser.add_argument("-store_decrypted", help="Where to store the decrypted text")

args=parser.parse_args()

kc_url = 'https://api.exequantum.com/api/kem'
aes_url = 'https://api.exequantum.com/api/aes'

if os.environ.get('ENVIRONMENT') == 'development':
    kc_url = 'http://localhost:8000/api/kem'
    aes_url = 'http://localhost:8000/api/aes'

def _decapsulate_key(cipher):
    """
    Call the API endpoint to decapsulate key and get the BYTES version of it.
    Needs the private key and cipher
    """
    api_url = kc_url + "/decapsulate_key"

    response = requests.post(api_url, headers={'Authorization': 'auth_token ' + os.environ.get('AUTH_TOKEN') }, json={'cipher': cipher.hex(), 'sk': open(args.secret, "r").read()})
    keys = response.json()

    return bytes.fromhex(keys['shared_key'])

def _generate_secret_from_private(cipher):
    """
    Returns the shared secret generated by the key decapsulation.
    Can be used then to decrypt data.
    """
    key = _decapsulate_key(cipher)
    
    return key

def _read_cipher():
    # Read the cipher that's stored somewhere
    cipher_path = args.cipher
    return open(cipher_path, "r").read()

def _decrypt_text(ciphertext):
    # Use AES to decrypt test using the private key and cipher
    cipher = _read_cipher()

    shared_key = _generate_secret_from_private(bytes.fromhex(cipher)) 

    return requests.post(aes_url + '/decrypt_text', headers={'Authorization': 'auth_token ' + os.environ.get('AUTH_TOKEN') }, json={'ciphertext': ciphertext, 'key': shared_key.hex()}).json()

def _decrypt_file(ciphertext_path):
    text = open(ciphertext_path, "r").read()

    return _decrypt_text(text)
    
def _store_decrypted_text(text, text_path):
    os.makedirs(os.path.dirname(text_path), exist_ok=True)
    f = open(text_path, "w")
    f.write(text)
    f.close()
    print('Decrypted text stored successfully')
    
def _store_decrypted_file(file, file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    with open(file_path, "wb") as binary_file:
        binary_file.write(file)
    print('Decrypted non-text file stored successfully')
    
def decrypt(): 
    # Collect it all together
    text = args.text
    file = args.file
    
    text_path = args.store_decrypted

    if text != None:
        _store_decrypted_text(_decrypt_text(text), text_path) 
    if file != None:
        if len(file.split('.')) != 1 and file.split('.')[1] == 'txt':
            _store_decrypted_text(_decrypt_file(file), text_path) 
        else:
            _store_decrypted_file(bytes.fromhex(_decrypt_file(file)), text_path) 
        
    return 'Success'

if __name__ == "__main__":
    # Can't decrypt both text and file. Must choose one or the other
    if(args.text != None and args.file != None):
        sys.exit('Error: you can only encrypt a file or text, not both')
    if args.store_decrypted == None or args.cipher == None or args.text == None and args.file == None:
        sys.exit('Error: please make sure to specify path for cipher (-cipher), secret key (-secret_path), where to store the decrypted text (-store_decrypted) and a file or text to decrypt')
    decrypt()  
