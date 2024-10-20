import requests
import os
import argparse, sys
import pdb
from dotenv import load_dotenv
load_dotenv()
parser=argparse.ArgumentParser()

parser.add_argument("-token", help="Specify path to store the temporary token")

args=parser.parse_args()

url = 'https://api.exequantum.com/api/token'

if os.environ.get('ENVIRONMENT') == 'development':
    url = 'http://localhost:8000/api/token'

def _fetch_token():
    """
    Generate the temporary token and return them as HEX.
    No info needed except for the auth token
    """
    api_url = url + "/new"
    response = requests.get(api_url, headers={'Authorization': 'auth_token ' + os.environ.get('AUTH_TOKEN') })

    return response.json()

def _store_token_key(token_key, token_path):
    os.makedirs(os.path.dirname(token_path), exist_ok=True)
    # Where the token_key is stored is subject to change based on use case.
    # The token key is sensitive information and therefore needs extra security when stored.
    f = open(token_path, "w")
    f.write(token_key)
    f.close()
    print('Stored token key successfully')
    
def generate_keys():
    token_key = _fetch_token()
    token_path = args.token
    _store_token_key(token_key['new_token'], token_path)

    
if __name__ == "__main__":
    if args.token == None:
        sys.exit('Error: please make sure to specify path for the token key (-token)')
    generate_keys()