# CRYSTALS-Kyber API Endpoint

This code implements an end-to-end encryption using CRYSTALS-Kyber and signs the keys using CRYSTALS-Dilithium. It generates the keys using ExeQ's API as well as encapsulates and decapsulates the keys for AES encryption. 

### Please use this code only for demo and trial purposes, not for practical production security.
### This API requires an auth token to be used. Please reach out to me for a token to try out this API.

## How does CRYSTALS-Kyber works?

CRYSTALS-Kyber does not perform the encryption itself. Instead, it generates a public and private key pair, which is then used to *encapsulate* and *decapsulate* the cipher to generate a shared secret that only the message sender and recipient hold.

<img width="426" alt="Screenshot 2024-03-05 at 1 12 47 pm" src="https://github.com/samuelnsam/CRYSTALs-Kyber-API/assets/87163496/54d41911-634d-437d-ac77-ca4d57e070c9">

## What does this code do?

This code allows users who have the API token to access ExeQ's API to generate a key pair and encasulate and decapsulate the keys. It also uses AES encryption with the shared key to encrypt and decrypt the message. It uses CRYSTALS-Dilithium to sign the public key and ensure origin.

## How do I use this code?

To use it, you need to have Python installed and a functioning command line pointed to the directory with the Python files.

You need to create an `.env` file that will contain the `AUTH_TOKEN` to authorize access to the API.

In order to see how to use the available tools, run the following commands:
```
python kyber_keys.py --help
python kyber_encrypt.py --help
python kyber_decrypt.py --help
```

First, we need to generate the public-private keypair, run the following command:

```
python kyber_keys.py -public public/public_key.txt -verif_signature signature/signature.txt -verif_key verif_key/verif_key.txt -secret secret/secret_key.txt
```

Note: This commande will store the public key in the file `public_key.txt` that's inside the directory `public` and the private key will be stored in a secret place. It will also store the verification signature and the verification public key in the chosent paths. Feel free to change the arguments as needed.

This command will be ran by the message *receiver* to send the public key to the sender to generate a cipher and the shared secret.

To encapsulate the key and generate a shared secret to use to encrypt a text, run the following command:

```
python kyber_encrypt.py -cipher cipher/cipher.txt -public public/public_key.txt -text <your text> -store_encrypted encrypted/message.txt -signature signature/signature.txt -verif_key verif_key/verif_key.txt
```

This is ran by the message *sender*, who will use the generated shared secret from the encapsulated key to encrypt the message and send it with a cipher for decapsulation.

If you want it to instead encrypt a text file, use:
```
python kyber_encrypt.py -cipher cipher/cipher.txt -public public/public_key.txt -file path/to/your/file -store_encrypted encrypted/message.txt -signature signature/signature.txt -verif_key verif_key/verif_key.txt
```

This reads the public key from where it was stored, stores the cipher in the chosen destination, and stores the encrypted file/text in the chosen destination.

To decapsulate the key and use it to decrypt the the message run:
```
python kyber_decrypt.py -cipher cipher/cipher.txt -file encrypted/message.txt -store_decrypted decrypted/message_plain.txt -public public/public_key.txt                                            
```

The *receiver* runs this command. Using the private key they never shared with the sender, as well as the cipher that was sent back by the sender, the receiver can decapsulate the key to generate the shared secret that can be used to decrypt the message.
