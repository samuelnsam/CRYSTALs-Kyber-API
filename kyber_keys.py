import requests
import os
import argparse, sys
from dotenv import load_dotenv
load_dotenv()
parser=argparse.ArgumentParser()

parser.add_argument("-public", help="Specify path to store the public key")
parser.add_argument("-private", help="Specify path to store the private key")

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
    
    return bytes.fromhex(keys['pk']), bytes.fromhex(keys['sk'])

def _store_public_key(public_key, public_path):
    os.makedirs(os.path.dirname(public_path), exist_ok=True)
    # Where the public_key is stored is subject to change based on use case.
    # The public key is NOT sensitive information and therefore won't need extra security when stored.
    f = open(public_path, "w")
    f.write(public_key.hex())
    f.close()
    print('Stored public key successfully')

def _store_private_key(secret_key, private_path):
    # Where the secret_key is stored is subject to change based on use case.
    # The secret_key is SENSITIVE information and therefore will need extra security when stored.
    os.makedirs(os.path.dirname(private_path), exist_ok=True)
    f = open(private_path, "w")
    f.write(secret_key.hex())
    f.close()
    print('Stored private key successfully')

def generate_keys():
    public_key, secret_key = _fetch_keys()
    public_path = args.public
    _store_public_key(public_key, public_path)
    
    private_path = args.private
    _store_private_key(secret_key, private_path)
    
if __name__ == "__main__":
    if args.private == None or args.public == None:
        sys.exit('Error: please make sure to specify path for cipher (-cipher), public key (-public) and private key (-private)')
    generate_keys()