# GPGHelper

GPGHelper provides a text-based frontend to GNU Privacy Guard, or GPG.

GPGHelper is still in very early development - consider this version 0.1.0. 
It was started on 2020-November-01.


## Requirements
GPGHelper is written for linux systems and requires `gpg` to be in the system path - checks for these will be added in later releases.
Your system should also have Python 3 installed and up to date.

GPGHelper can be run with `python gpghelper.py`


## Usage
### Key Management
The key management section provides functions for generating, importing, exporting, listing, and deleting keys.


#### Key Generation
Key generation currently only supports RSA-4096.
You will be prompted for your name, email address, and password; and a keypair will be automatically generated and added to the keyring.

A revocation certificate will be created in your home directory.

#### Importing Keys
Keys can be imported from either an ASCII-Armor keyfile or a binary keyfile.
Type a filename, and the data will be imported if the key is valid.

Everything works under the hood for importing keys, but there is a known issue with the UI which mainly occurs when the key is already in the keyring.
This will be fixed when I find the time.


#### Exporting Keys
A list of all keys will be displayed.

Select whether you want to export a public key or a private key, then enter the number of the key to export.
Exporting private keys will require you to enter the passphrase to decrypt that key.
Public keys can be exported without a passphrase.

You will be prompted for a filename to export the key to, and the key will be exported as ASCII-Armor.
Binary keyfiles are not currently supported.


#### Listing Keys
There isn't anything special here - all of the public and private keys in your keyring are listed.


#### Deleting Keys
A list of the keys in your keyring will be shown.

Specify whether you want to delete a private or a public key, and then enter the number of that key and it will be deleted from your keyring.


### Encryption
A list of the public keys in your keyring will be displayed.
Enter the number of the key for each recipient you want to encrypt for, one key at a time.
Remember to include yourself in the recipients if you want to be able to decrypt the data.

Confirm the recipients, enter a file to encrypt and the name of an output file, and the data will be encrypted as ASCII-Armor.
Encryption to binary is not currently supported.


### Decryption
You will be prompted for a file to decrypt.
GPGHelper will check the file against your private keys and, if a match is found, will prompt you for the passphrase for that private key.
The file will then be decrypted to the specified output file.

If no matching private key is found, there is still an option to try to decrypt the file (for example, if you are a hidden recipient).


### Signing
You will be prompted for a file to sign, and asked which private key to use.
The signed file will be written to your specified output file as ASCII-Armor.


### Verifying
You will be prompted for a file to verify.
The signature will be checked and if it is valid, the email and fingerprint of the signing key will be printed.
Otherwise, GPGHelper will tell you the signature could not be verified.


## To Do
#### Fixes and Cleanup
* Move pieces of repetitive code into functions (e.g. getting a file from the user)
* Add quotes around user input before we pass it to system commands
* Add standard error messages and outputs in variables instead of having it typed out each time
* Tidy up a lot of the comments and add better explainations
* Fix the function for importing keys - backend works but success/failure messages are inconsistent
* There are a number of UI/UX issues and inconsistencies to fix
* Add function to check system requirements (GPG installed, POSIX system)
* Check return value of GPG for success

#### Features
* Support for subkeys
* Support for more key algorithms when generating a new key
* Text editor functionality, so that the user can type a message to encrypt instead of entering filenames
* Ability to import revocation certificates
* Keyserver support
* Setup script to install to system path
