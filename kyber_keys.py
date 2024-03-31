import requests
import os
import argparse, sys
from dotenv import load_dotenv
load_dotenv()
parser=argparse.ArgumentParser()

parser.add_argument("-public", help="Specify path to store the public key")
parser.add_argument("-verif_signature", help="Specify path to store the verification signature")
parser.add_argument("-verif_key", help="Specify path to store the private key")

args=parser.parse_args()

url = 'https://www.exequantum.com/api/kc'

if os.environ.get('ENVIRONMENT') == 'development':
    url = 'http://localhost:8000/api/kc'

def _fetch_keys():
    """
    Generate the key pair and return them as BYTES.
    No info needed except for the auth token
    """
    api_url = url + "/generate_keys"
    response = requests.get(api_url, headers={'Authorization': 'auth_token ' + os.environ.get('AUTH_TOKEN') })
    keys = response.json()

    return bytes.fromhex(keys['pk']), bytes.fromhex(keys['verification_key']), bytes.fromhex(keys['verification_signature'])

def _store_public_key(public_key, public_path):
    os.makedirs(os.path.dirname(public_path), exist_ok=True)
    # Where the public_key is stored is subject to change based on use case.
    # The public key is NOT sensitive information and therefore won't need extra security when stored.
    f = open(public_path, "w")
    f.write(public_key.hex())
    f.close()
    print('Stored public key successfully')
    
def _store_verification_signature(signature, sig_path):
    # Where the verification signature is stored is subject to change based on use case.
    # The verification signature is NOT sensitive information and therefore will not need extra security.
    os.makedirs(os.path.dirname(sig_path), exist_ok=True)
    f = open(sig_path, "w")
    f.write(signature.hex())
    f.close()
    print('Stored verification signature successfully')
    
def _store_verification_key(signature, sig_path):
    # Where the verification signature is stored is subject to change based on use case.
    # The verification signature is NOT sensitive information and therefore will not need extra security.
    os.makedirs(os.path.dirname(sig_path), exist_ok=True)
    f = open(sig_path, "w")
    f.write(signature.hex())
    f.close()
    print('Stored verification signature successfully')

def generate_keys():
    public_key, verif_key, signature = _fetch_keys()
    public_path = args.public
    _store_public_key(public_key, public_path)
    
    _store_verification_signature(signature, args.verif_signature)
    
    _store_verification_key(verif_key, args.verif_key)
    
if __name__ == "__main__":
    if args.verif_key == None or args.verif_signature == None or args.public == None:
        sys.exit('Error: please make sure to specify path for the public key (-public), verification signature (-verif_signature) and verification key (-verif_key)')
    generate_keys()