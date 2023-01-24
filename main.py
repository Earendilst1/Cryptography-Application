"""Coursework for 22547835 1CWK50
Student name:Esther Chidinma Okeke 
Student ID:22547835
This application was developed using code samples from:
70% https://gnupg.readthedocs.io/en/latest/
10% //https://gnupg.readthedocs.io/en/latest/#setting-the-trust-level-for-imported-keys
10% https://unix.stackexchange.com/questions/607240/what-does-it-mean-by-gpg-encrypting-a-file-with-multiple-recipients
10% from youtube videos.
All comments are original"""
import argparse
import os
from pathlib import Path

import gnupg
import shutil

DATA_HOME = os.getenv("GPG_DATA_PATH", "./data")

GPG_HOME = f"{DATA_HOME}/gpg"
PUBLIC_KEY_FILE = f"{DATA_HOME}/public_key.pem"


# Initialize GnuPG and program's work directory. It creates the "./data" folder when the first command is run.
# By default, it creates it automatically ./data if it does not exist. 
def init_data():
    global gpg
    data_path = Path(GPG_HOME)
    if data_path.exists() is False:
        print(f"Missing Application data path '{data_path.resolve()}'. Creating one....")
        data_path.mkdir(parents=True, exist_ok=True)
    gpg = gnupg.GPG(gnupghome=GPG_HOME)
    gpg.encoding = 'utf-8'


# Imports an existing user's public key, needed for file encryption and signature verification.
# This request a parameter file which is to be imported, failure to provide such will give an error output.
def import_public_key(public_key_file: str):
    if public_key_file is None or public_key_file.strip() == "":
        println(f"No key file specified for import", error=True)
        return

    result = gpg.import_keys_file(key_path=public_key_file)
    print(f"{result.count} public keys imported from file {public_key_file}")

    trust_finger_prints = []
    for imp in result.results:
        ok = imp.get("ok", None)
        if ok:
            trust_finger_prints.append(imp.get("fingerprint"))
            println(f"Public key imported -> {imp}")
        else:
            println(f"Failed to import public key -> {imp}")

    if result.returncode != 0:
        println(f"Failed to import public keys in file '{public_key_file}'. Reason code {result.returncode}",
                error=True)

    # Trust keys are set at the highest trust level for fingerprints of
    # imported keys. 
    gpg.trust_keys(trust_finger_prints, "TRUST_ULTIMATE")
    println("Public Key file import successful. Listing all keys...")
    list_public_keys()
    return


# This Generate new RSA-2048 Key Pair for a user, requesting as input a name or email to store the keys with.
def generate_keys(email: str):
    # TODO: Add key passphrase
    # TODO: Set key expiry
    data = gpg.gen_key_input(key_type="RSA", key_length=2048, name_real=email,
                             name_email=email, no_protection=True)
    return gpg.gen_key(data)


# List all users public keys existing in the system, both generated and imported users keys.
def list_public_keys():
    public_keys = gpg.list_keys(False)
    if public_keys is None or len(public_keys) == 0:
        println("No public keys found in the key store.")
        return
    println(f"============ {len(public_keys)} public keys found ============")
    for k in public_keys:
        println(f"[Email/Alias]: {extract_alias(k)}")
        println(f"[Public Key Details]:  {k}")
        println("")


# Compress folder to zip file before encrypting.
def compress_folder(folder_path: str, zip_file_name: str) -> str:
    println(f"Compressing folder '{folder_path}'")
    zip_file = shutil.make_archive(zip_file_name, 'zip', folder_path)
    println(f"Folder compressed to {zip_file}")
    return zip_file


# Encrypt file using the public keys of the users/recipients specified
def encrypt(file_path: str, key_aliases: list[str]):
    #  https://unix.stackexchange.com/questions/607240/what-does-it-mean-by-gpg-encrypting-a-file-with-multiple-recipients

    println(f"Encrypting compressed file {file_path} with public key aliases {key_aliases}..")
    if key_aliases is None or len(key_aliases) == 0:
        println("No user key aliases specified. Aborting encryption", True)
        return

    enc_file = f"{file_path}.enc"

    with open(file_path, 'rb') as f:

        # Encrypt compressed file
        enc_result = gpg.encrypt_file(f, recipients=key_aliases, armor=False,
                                      output=enc_file)
        if enc_result.returncode != 0:
            println(f"Failed to encrypt file '{file_path}', "
                    f"with error code '{enc_result.returncode}' -> {enc_result.status}")
            return
        println(f"File encryption done. Encrypted file -> {enc_file}")

        # TODO: Sign the clear file and compress signature
        sign(enc_file)


# This Creates a detached signature of the file specified using the private/application keys and returns a failure message if unsuccessful.
def sign(file_path: str):
    println(f"Signing file {file_path}")
    detached_sign_file = f"{file_path}.sig"

    sig_result = gpg.sign_file(file_path, output=detached_sign_file, detach=True)
    if sig_result.returncode != 0:
        println(f"Failed to sign file '{file_path}', "
                f"with error code '{sig_result.returncode}' -> {sig_result.status}")
        return
    println(f"Signing done. Signature file -> {detached_sign_file}")


# Decrypt the file using the private/application keys
def decrypt(enc_file_path: str):
    path = Path(enc_file_path)
    if path.exists() is False or path.is_dir():
        println(f"Invalid encrypted file path '{enc_file_path}'")
        return

    println(f"Decrypting file {enc_file_path}...")
    with open(enc_file_path, 'rb') as f:
        decrypted_data = gpg.decrypt_file(f)
        decrypted_file = f"{path.parent.resolve()}/decrypted_{path.stem}"
        with open(decrypted_file, 'wb') as e:
            e.write(decrypted_data.data)
            println(f"File decrypted -> {decrypted_file}...")


# This verifies a detached signature of a file. This is usually achieved with the user's public keys after decrypting.
def verify(file_path: str):
    path = Path(file_path)
    sig_path = Path(f"{file_path}.sig")
    if path.exists() is False or path.is_dir():
        println(f"Verification failed. Invalid Data file path '{file_path}'.")
        return
    if sig_path.exists() is False or sig_path.is_dir():
        println(f"Verification failed. Invalid Signature file path '{sig_path}'."
                f" Signature file needs to exist in the same directory as the data file")
        return
    with open(sig_path, 'rb') as f:
        verified = gpg.verify_file(f, data_filename=file_path)
        if not verified:
            println(f"Could not verify signature for file {file_path}", True)
            return
        println("=======Signature Found=======")
        println(f"Status: {verified.status}")
        println(f"Signature ID: {verified.signature_id}")
        println(f"Fingerprint: {verified.fingerprint}")
        println(f"Signer Username: {verified.username}")
        println(f"Valid: {verified.valid}")
        println(f"Trust Level: {verified.trust_text}")
        println(f"Signature Timestamp: {verified.sig_timestamp}")
        println(f"Signature Creation Date: {verified.creation_date}")
        println(f"Metadata: {verified.sig_info}")


# Initialize user and application keys
def init_user():
    keys = gpg.list_keys(True)
    if keys and len(keys) > 0:
        println(f"Application Key already initialized in data folder '{DATA_HOME}' "
                f"with key alias '{extract_alias(keys[0])}'")
        return

    println("No application keys found, attempting to generate keys......")
    email = input("\nEnter User Email (will be used as a key alias and included in the generated keys):")

    if email is None or email.strip() == "":
        println(f"Invalid email '{email}' provided", True)
        return

    println(f"Generating RSA 2048-bit keys for user '{email}'......")
    key_result = generate_keys(email=email)
    if key_result.returncode != 0:
        println(f"Failed to generate key, returned error code {key_result.returncode} - [{key_result.status}]", True)
        return

    with open(PUBLIC_KEY_FILE, 'w') as f:
        pk = gpg.export_keys([email])
        f.write(pk)

    println(f"Key generated for user '{email}', Fingerprint: {key_result.fingerprint}")
    println(f"Application public key file generated -> '{PUBLIC_KEY_FILE}'")
    println(f"Application initialized in data folder -> {DATA_HOME}")


# Initialize program defined CLI arguments
def init_args():
    parser = argparse.ArgumentParser(
        prog='EncryptDecrypt',
        description='Multi-Key Encryption and Decryption Program',
        epilog='Text at the bottom of help')

    parser.add_argument("-c", "--command", choices=["init", "list-recipient-keys", "add-recipient-key", "encrypt",
                                                    "decrypt", "verify"],
                        required=True,
                        help="""Program command. Supported values are: \n
                        [init] -> Initialize RSA-2048 application keys, 
                        [list-recipient-keys] -> List recipient public keys including imported,
                        [add-recipient-key] -> Import recipient public keys via PEM file,
                        [encrypt] -> Encrypt files/folder using recipient public keys,
                        [decrypt] -> Decrypt files using application key, 
                        [verify] -> Verify encrypted files signatures and checksum""")
    parser.add_argument("--key-file", help="Recipient public key PEM file to import")
    parser.add_argument("--file", help="Absolute path for file to encrypt/decrypt/verify")
    parser.add_argument("--folder", help="Absolute path for folder/file to encrypt")
    parser.add_argument("--recipient", action='append', help="Aliases of recipient public keys to encrypt the data. "
                                                             "Parameter support multiple values")

    return parser.parse_args()

# Run the app
def run():
    args = init_args()
    init_data()

    if args.command == "init":
        init_user()
        return
    if args.command == "list-recipient-keys":
        list_public_keys()

    if args.command == "add-recipient-key":
        import_public_key(args.key_file)
        return

    if args.command == "decrypt":
        decrypt(args.file)

    if args.command == "encrypt":
        file_path = args.file
        if args.folder:
            file_path = compress_folder(args.folder, args.folder)
        encrypt(file_path, args.recipient)
        return
    if args.command == "verify":
        verify(args.file)


def println(t: str, error: bool = False):
    print(f"{'[ERROR]' if error else ''}{t}")


def extract_alias(k: dict) -> str:
    return k['uids'][0].split('<')[0].strip()


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    run()
