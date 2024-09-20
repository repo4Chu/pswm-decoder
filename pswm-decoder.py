import cryptocode

PASS_VAULT_FILE = '.local/share/pswm/pswm'
WORDLIST_PATH = '/usr/share/wordlists/rockyou.txt'

def get_encrypted_vault():
    with open(PASS_VAULT_FILE, 'r') as file:
        return file.read()

def try_password(password, encrypted_text):
    decrypted_text = cryptocode.decrypt(encrypted_text, password)
    if decrypted_text:
        print(f"Password: {password}")
        print(f"Decoded text:\n{decrypted_text}")
        return True
    return False

def brute_force_with_wordlist():
    encrypted_text = get_encrypted_vault()
    with open(WORDLIST_PATH, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            password = line.strip()
            if try_password(password, encrypted_text):
                return
    print("not found.")
brute_force_with_wordlist()
