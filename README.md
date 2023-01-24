# EncryptDecrypt program

This program allows a user:
- Encrypt files/folders for single or multiple recipients
- Decrypt files using private keys
- Sign files for integrity check
- Verify file signatures
- Import other user keys for file encryption and signature verification

## Requirements
- Install GnuPG binary release https://gnupg.org/download/index.html
- Install Python 3 (3.9 and above) https://www.python.org/downloads/
- Install Pip https://pip.pypa.io/en/stable/installation/
- Run `pip install -r ./requirements.txt`

## Example:

- Initialize application (generated recipient key can be found in ./data.public_key.pem)
`python main.py --command=init`

- Add other recipient Public Key file
`python main.py --command=add-recipient-key --key-file=./alice.pem`
`python main.py --command=add-recipient-key --key-file=./bob.pem`

- List Recipient Public  Keys:
`python main.py --command=list-recipient-keys`


- Encrypt file/folder
`python main.py --command=encrypt --folder=./test --recipient=Bob@test.com --recipient=Alice@test.com`

- Decrypt file
`python main.py --command=decrypt --file=./test.zip.enc`


- Verify file
`python main.py --command=verify --file=./test.zip.enc`
