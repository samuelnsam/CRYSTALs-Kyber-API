import requests
import argparse
import os, sys
from dotenv import load_dotenv
load_dotenv()
parser=argparse.ArgumentParser()

parser.add_argument("-text", help="Text to sign")
parser.add_argument("-public_key", help="Path to store the public key")
parser.add_argument("-secret_key", help="Path to store the secret key")
parser.add_argument("-signature", help="Specify path to store the signature")


args=parser.parse_args()

url = 'https://api.exequantum.com/api/signature'

if os.environ.get('ENVIRONMENT') == 'development':
    url = 'http://localhost:8000/api/signature'

def _sign(data):
    api_url = url + "/sign"
    response = requests.post(api_url, headers={'Authorization': 'auth_token ' + os.environ.get('AUTH_TOKEN') }, json={ 'data': data })
    signature = response.json()
    return signature['signature'], signature['pk'], signature['sk']

def sign():
    # Putting it all together
    signature, pk, sk = _sign(args.text)
    os.makedirs(os.path.dirname(args.signature), exist_ok=True)
    f = open(args.signature, "w")
    f.write(signature)
    f.close()
    os.makedirs(os.path.dirname(args.public_key), exist_ok=True)
    f = open(args.public_key, "w")
    f.write(pk)
    f.close()
    os.makedirs(os.path.dirname(args.secret_key), exist_ok=True)
    f = open(args.secret_key, "w")
    f.write(sk)
    f.close()
    print('Successfully stored signature')

if __name__ == "__main__":
    if args.text == None or args.signature == None:
        sys.exit('Error: please make sure to specify path for the signature to be stored (-signature), public key (-public_path), and the text to sign (-text)')
    sign()  
