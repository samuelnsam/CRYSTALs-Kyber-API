import requests
import argparse
import os, sys
from dotenv import load_dotenv

load_dotenv()
parser=argparse.ArgumentParser()

parser.add_argument("-cipher", help="Specify path to store the cipher")
parser.add_argument("-public", help="Specify path to read the public key")
parser.add_argument("-signature", help="The path signature to confirm key origin")
parser.add_argument("-verif_key", help="The path to key to confirm key origin")
parser.add_argument("-text", help="Specify text to encrypt (if not file)")
parser.add_argument("-file", help="Specify file to encrypt (if not text)")
parser.add_argument("-store_encrypted", help="Where to store the encrypted text")

args=parser.parse_args()

kc_url = 'https://www.exequantum.com/api/kc'
aes_url = 'https://www.exequantum.com/api/aes'

if os.environ.get('ENVIRONMENT') == 'development':
    kc_url = 'http://localhost:8000/api/kc'
    aes_url = 'http://localhost:8000/api/aes'

def _encapsulate_key(pk, signature, verify_key):
    """
    Call the API endpoint to encapsulate the key, using the public key and signature for verification. 
    This generates a cipher and a shared key if the origin of the key is verified.
    """
    api_url = kc_url + "/encapsulate_key"
    response = requests.post(api_url, headers={'Authorization': 'auth_token ' + os.environ.get('AUTH_TOKEN') }, json={ 'verif_key': verify_key, 'pk': pk, 'signature': signature })
    keys = response.json()
    return bytes.fromhex(keys['cipher']), bytes.fromhex(keys['shared_key'])

def _generate_shared_key_cipher():
    """
    Use the public key to generate the cipher and shared key.
    Includes calling the API endpoint to do so.
    """
    public_path = args.public
    p_key = open(public_path, "r").read()
    sig_path = args.signature
    signature = open(sig_path, "r").read()
    verif_key_path = args.verif_key
    verif_key = open(verif_key_path, "r").read()
    cipher, key = _encapsulate_key(p_key, signature, verif_key)
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

    return requests.post(aes_url + '/encrypt_text', headers={'Authorization': 'auth_token ' + os.environ.get('AUTH_TOKEN') }, json={'unencrypted': text, 'key': shared_key.hex()}).json()

def _store_encrypted_text(enc_text, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    f = open(path, "w")
    f.write(enc_text)
    f.close()
    print('Encrypted text stored successfully')

def _encrypt_file(file, shared_key):
    with open(file,'rb') as f:
        plain_file = f.read()

    encrypted_content = _encrypt_text(plain_file.hex(), shared_key)

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
