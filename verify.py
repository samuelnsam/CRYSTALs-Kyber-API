import requests
import argparse
import os, sys
from dotenv import load_dotenv
load_dotenv()
parser=argparse.ArgumentParser()

parser.add_argument("-text", help="Text to verify")
parser.add_argument("-public_key", help="Path where the public key is stored")
parser.add_argument("-signature", help="Path where signature is stored")

args=parser.parse_args()

url = 'https://www.exequantum.com/api/signature'

if os.environ.get('ENVIRONMENT') == 'development':
    url = 'http://localhost:8000/api/signature'

def _verify(message, pk, signature):
    api_url = url + "/verify"
    response = requests.post(api_url, headers={'Authorization': 'auth_token ' + os.environ.get('AUTH_TOKEN') }, json={ 'message': message, 'pk': pk, 'signature': signature })
    return response.json()['verified']

def verify():
    # Putting it all together
    pk = open(args.public_key, "r").read()
    sign = open(args.signature, "r").read()
    signature = _verify(args.text, pk, sign)

    print(signature)

if __name__ == "__main__":
    if args.text == None or args.signature == None:
        sys.exit('Error: please make sure to specify path for the signature to be stored (-signature), public key (-public_path), and the text to sign (-text)')
    verify()  
