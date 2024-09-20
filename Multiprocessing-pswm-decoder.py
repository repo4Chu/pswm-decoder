from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from multiprocessing import Pool
from tqdm import tqdm
import tarfile

def decrypt(password):
    try:

        # generate the private key from the password and salt

        private_key = hashlib.scrypt(
            password.strip().encode(),
            salt=salt,
            n=2 ** 14,
            r=8,
            p=1,
            dklen=32,
            )

        # create the cipher config

        cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

        # decrypt the cipher text

        decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    except:
        return False
    
    split_lines = []
    for line in decrypted.decode('UTF-8').split('\n'):
        split_lines.append(line.split('\t'))
    
    return [password, split_lines]

def init_worker(lsalt, lcipher_text, lnonce, ltag,):
    #start each child here to initialize the same variable, RANGEOFINTS.
    global salt, cipher_text, nonce, tag
    salt = lsalt
    cipher_text = lcipher_text
    nonce = lnonce
    tag = ltag

def bruteforce(encrypted_text,rockyou_file):
    encrypted_text_array = encrypted_text.split('*')
    encrypted_dict = {
        'cipher_text': encrypted_text_array[0],
        'salt': encrypted_text_array[1],
        'nonce': encrypted_text_array[2],
        'tag': encrypted_text_array[3],
        }

    # decode the dictionary entries from base64

    salt = b64decode(encrypted_dict['salt'])
    cipher_text = b64decode(encrypted_dict['cipher_text'])
    nonce = b64decode(encrypted_dict['nonce'])
    tag = b64decode(encrypted_dict['tag'])
    
    rockyou_lines = []
    
    with tarfile.open(rockyou_file, "r:gz") as t:
        member = t.getmember('rockyou.txt')
        rockyou_content = t.extractfile(member)
        if rockyou_content is not None:
            rockyou_lines = rockyou_content.read().decode("unicode_escape").split("\n")
        else:
            return "rockyou.txt.tar.gz file is not found, empty or corrupt"
    
    with Pool(initializer=init_worker, initargs=(salt, cipher_text, nonce, tag,)) as bigpool:
        results = tqdm(bigpool.imap_unordered(decrypt, rockyou_lines, 2), total=len(rockyou_lines), miniters=1,dynamic_ncols=False,ncols=100,smoothing=0,unit="Integers",unit_scale=False,leave=True)
        for result in results:
            if result:
                return result
                bigpool.terminate()
                bigpool.join()
                break
    return False

def main():
    PASS_VAULT_FILE = "pswm.txt"
    rockyou_file = "rockyou.txt.tar.gz"
    if not (os.path.isfile(PASS_VAULT_FILE) and os.path.getsize(PASS_VAULT_FILE) > 0 and os.path.isfile(rockyou_file) and os.path.getsize(rockyou_file) > 0):
        print("missing or empty vault file!")
        return
    else:
        with open(PASS_VAULT_FILE,"r") as f:
            encrypted_text = f.read().strip()
        result = bruteforce(encrypted_text,rockyou_file)
        if result:
            print('bruteforce password:', result[0])
            for idx,linearray in enumerate(result[1]):
                print('\npswm decrypted line number', idx, '\nalias:', linearray[0], '\nUsername:', linearray[1], '\nPassword:', linearray[2])

if __name__ == "__main__":
    main()

