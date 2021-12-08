import re
import sys
import string
import secrets
import getpass
import argparse
import psycopg2
import configparser
from pbkdf2 import PBKDF2
from hashlib import sha256
from Crypto.Cipher import AES
from base64 import b64encode, b64decode


def connect(db_host, db_name, db_user, master_password):
    """Connecting to database"""
    db_password = master_password

    try:
        conn = psycopg2.connect(
                        dbname=db_name, 
                        user=db_user, 
                        password=db_password, 
                        host=db_host)
    except Exception as _exc:
        print("[INFO] Unable to connect to database", _exc)
        sys.exit()

    return conn


def add_entry(conn, url, login, encrypted_password):
    """Add entry(url, login, password) into vault"""
    with conn.cursor() as cur:
        try:
            cur.execute("""INSERT INTO vault (url, login, password) VALUES (%s, %s, %s)""", (url, login, encrypted_password))
        except Exception as _exc:
            return f"[INFO] An error occurred while adding password into vault ({_exc})"
        
    return "[INFO] Data was successfully added"


def get_entry(conn, url, salt, master_password, urls):
    """Getting an entry from vault by url"""
    if url in urls:
        with conn.cursor() as cur:
            try:
                cur.execute("""SELECT * FROM vault WHERE url = %s""", (url,))

                data = cur.fetchone()
                encrypted_password = data[2]
                decrypted_password = decrypt_password(salt, encrypted_password, master_password).decode('utf-8')
            except Exception as _exc:
                return f"[INFO] An error occurred while getting entry from vault ({_exc})"

        return f"URL: {data[0]}, login: {data[1]}, password: {decrypted_password}"
    else:
        return "[INFO] No such url in vault"


def get_all_entries(conn, salt, master_password):
    """Getting all entries from vault"""
    with conn.cursor() as cur:
        try:
            cur.execute("""SELECT * FROM vault""")

            data = cur.fetchall()
        except Exception as _exc:
            return f"[INFO] An error occurred while getting entries from vault ({_exc})"

    for i in range(len(data)):
        encrypted_password = data[i][2]
        decrypted_password = decrypt_password(salt, encrypted_password, master_password).decode('utf-8')

        return f"URL: {data[i][0]}, login: {data[i][1]}, password: {decrypted_password}"


def delete_entry(conn, url, urls):
    """Deleting entry from vault"""
    if url in urls:
        with conn.cursor() as cur:
            try:
                cur.execute("""DELETE FROM vault where url = %s""", (url,))
            except Exception as _exc:
                return f"[INFO] An error occurred while deleting entry from vault ({_exc})"

        return "[INFO] Data was successfully deleted"
    else:
        return "[INFO] No such url in vault"


def update_url(conn, new_url, old_url, urls):
    """Updating entry's url"""
    if old_url in urls:
        with conn.cursor() as cur:
            try:
                cur.execute("""UPDATE vault SET url = %s WHERE url = %s""", (new_url, old_url))
            except Exception as _exc:
                return f"[INFO] An error occurred while updating URL ({_exc})"

        return "[INFO] URL was successfully updated"
    else:
        return "[INFO] No such url in vault"


def update_login(conn, url, new_login, urls):
    """Updating entry's login"""
    if url in urls:
        with conn.cursor() as cur:
            try:
                cur.execute("""UPDATE vault SET login = %s WHERE url = %s""", (new_login, url))
            except Exception as _exc:
                return f"[INFO] An error occurred while updating login ({_exc})"

        return "[INFO] login was successfully updated"
    else:
        return "[INFO] No such url in vault"


def update_password(conn, url, encrypted_new_password, urls):
    """Updating entry's password"""
    if url in urls:
        with conn.cursor() as cur:
            try:
                cur.execute("""UPDATE vault SET password = %s WHERE url = %s""", (encrypted_new_password, url))
            except Exception as _exc:
                return f"[INFO] An error occurred while updating password ({_exc})"

        return "[INFO] Password was successfully updated"
    else:
        return "[INFO] No such url in vault"


def create_vault(conn, table_names):
    """Creating database table (vault)"""
    if len(table_names) == 0:
        with conn.cursor() as cur:
            try:
                cur.execute("""CREATE TABLE vault(
                                    url varchar(255),
                                    login varchar(255),
                                    password varchar(255));""")
            except Exception as _exc:
                return f"[INFO] An error occurred while creating vault ({_exc})"

        return "[INFO] Vault was successfully created"
    else:
        return "[INFO] Vault already exists"


def delete_vault(conn, table_names):
    """Deleting database table (vault)"""
    if len(table_names) > 0:
        with conn.cursor() as cur:
            try:
                cur.execute("""DROP TABLE vault""")
            except Exception as _exc:
                return f"[INFO] An error occurred while deleting vault ({_exc})"

        return "[INFO] Vault was successfully deleted"
    else:
        return "[INFO] No vault was found"


def pass_gen(password_length):
    """Generating secure password"""
    symbols = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(symbols) for i in range(password_length))

    return password


def get_table_names(conn):
    """Getting tables from database"""
    table_names = []

    with conn.cursor() as cur:
        try:
            cur.execute("""SELECT * FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema'""")
            tables = cur.fetchall()
        except Exception as _exc:
            return "[INFO] An error occurred while getting tables"
        
    for table in range(len(tables)):
        table_names.append(tables[table][1])
    
    return table_names


def get_urls_and_passwords(conn, salt, master_password):
    """Getting urls and passwords from vault"""
    urls_and_passwords = {}

    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT url, password FROM vault """)

            data = cur.fetchall()
    except Exception as _exc:
        return f"[INFO] An error occurred while getting logins and passwords from vault ({_exc})"
    
    for entry in data:
        url, encrypted_password = entry[0], entry[1]
        decrypted_password = decrypt_password(salt, encrypted_password, master_password).decode('utf-8')
        urls_and_passwords[url] = decrypted_password

    return urls_and_passwords


def health_check(passwords, urls_and_passwords):
    """Checking passwords health"""
    reused_passwords_accounts = []
    weak_passwords_accounts = []

    for url, password in urls_and_passwords.items():
        if passwords.count(password) > 1:
            reused_passwords_accounts.append(url)

    for url, password in urls_and_passwords.items():
        length_check = len(password) > 8
        digits_check = re.search(r"\d", password) is not None
        lowercase_check = re.search(r"[a-z]", password) is not None
        uppercase_check = re.search(r"[A-Z]", password) is not None
        symbol_check = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is not None

        if not (length_check and digits_check and lowercase_check and uppercase_check and symbol_check):
            weak_passwords_accounts.append(url)

    return reused_passwords_accounts, weak_passwords_accounts


def get_hash(master_password):
    """Getting master passwords's hash"""
    encoded_master_password = master_password.encode()
    master_password_hash = sha256(encoded_master_password).hexdigest()

    return master_password_hash


def encrypt_password(salt, password_to_encrypt, master_password):
    """Encrypting password"""
    master_password_hash = get_hash(master_password)
    key = PBKDF2(str(master_password_hash), salt).read(32)
    data_convert = str.encode(password_to_encrypt)
    cipher = AES.new(key, AES.MODE_EAX) 
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data_convert) 
    add_nonce = ciphertext + nonce
    encoded_ciphertext = b64encode(add_nonce).decode()

    return encoded_ciphertext


def decrypt_password(salt, password_to_decrypt, master_password): 
    """Decrypting password"""
    master_password_hash = get_hash(master_password)
    
    if len(password_to_decrypt) % 4:
        password_to_decrypt += '=' * (4 - len(password_to_decrypt) % 4)

    convert = b64decode(password_to_decrypt)
    key = PBKDF2(str(master_password_hash), salt).read(32)
    nonce = convert[-16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(convert[:-16]) 

    return plaintext


def parse_args(argv):
    """Parsing arguments from command prompt"""
    parser = argparse.ArgumentParser(description='Run password manager vault')
    parser.add_argument("-a", "--add", type=str, nargs=3, help="Add a new entry into the vault", metavar=("[URL]", "[login]", "[PASSWD]"))
    parser.add_argument("-g", "--get", type=str, nargs = 1, help="Get an entry by URL from vault", metavar=("[URL]"))
    parser.add_argument("-d", "--delete", type=str, nargs=1, help="Delete an entry from vault by URL", metavar=("[URL]")) 
    parser.add_argument("-ga", "--get_all", action="store_true", help="Get all data from vault")
    parser.add_argument("-uu", "--update_url", type=str, nargs=2, help="Update an URL", metavar=("[OLD_URL]", "[NEW_URL]"))
    parser.add_argument("-ul", "--update_login", type=str, nargs=2, help="Update a login in account", metavar=("[URL]", "[NEW_login]")) 
    parser.add_argument("-up", "--update_password", type=str, nargs=2, help="Update a password in account", metavar=("[URL]", "[NEW_PASSWORD]"))
    parser.add_argument('-gp', '--generate_password', type=str, nargs=1, help="Generate secure password", metavar=("[LENGTH]"))
    parser.add_argument("-hc", "--health_check", action='store_true', help="Check passwords health")
    parser.add_argument("-cv", "--create_vault", action='store_true', help="Create vault")
    parser.add_argument("-dv", "--delete_vault", action='store_true', help="Delete vault")
    args = parser.parse_args(argv[1:])

    return args


def parse_config():
    """Parsing config file"""
    config = configparser.ConfigParser()
    config.read('settings.ini')

    settings = [config["Settings"]["db_host"][1:-1], config["Settings"]["db_name"][1:-1], config["Settings"]["db_user"][1:-1]]

    return settings


def main():
    """Main function"""
    master_password = getpass.getpass(prompt="Enter Master Password: ")

    args = parse_args(sys.argv)

    settings = parse_config()
    db_host, db_name, db_user = settings[::]

    salt = b'mysalt'

    conn = connect(db_host, db_name, db_user, master_password)

    conn.autocommit = True

    table_names =  get_table_names(conn)

    if len(table_names) > 0:
        urls_and_passwords = get_urls_and_passwords(conn, salt, master_password)
        passwords = [passwd for passwd in urls_and_passwords.values()]
        urls = [url for url in urls_and_passwords.keys()]

    if args.add:
        url, login, password = args.add[::]
        encrypted_password = encrypt_password(salt, password, master_password)

        print(add_entry(conn, url, login, encrypted_password))
        
    if args.get:
        url = args.get[0]

        print(get_entry(conn, url, salt, master_password, urls))

    if args.get_all:
        print(get_all_entries(conn, salt, master_password))

    if args.delete:
        url = args.delete[0]

        print(delete_entry(conn, url, urls))

    if args.update_url:
        old_url, new_url = args.update_url[::]

        print(update_url(conn, new_url, old_url, urls))

    if args.update_login:
        url, new_login = args.update_login[::]
        
        print(update_login(conn, url, new_login, urls))

    if args.update_password:
        url, new_password = args.update_password[::]

        encrypted_new_password = encrypt_password(salt, new_password, master_password)

        print(update_password(conn, url, encrypted_new_password, urls))

    if args.create_vault:
        print(create_vault(conn, table_names))

    if args.delete_vault:
        print(delete_vault(conn, table_names))

    if args.generate_password:
        password_length = int(args.generate_password[0])
        password = pass_gen(password_length)

        print(password)
    
    if args.health_check:
        reused_passwords_accounts, weak_passwords_accounts = health_check(passwords, urls_and_passwords)

        if len(reused_passwords_accounts) > 0:
            print("Accounts with reused passwords:")
            print(*reused_passwords_accounts, sep=', ')
        else:
            print("No accunts with reused passwords")
        
        if len(weak_passwords_accounts) > 0:
            print("Accounts with weak passwords:")
            print(*weak_passwords_accounts, sep=', ')
        else:
            print("No accounts with weak passwords")


if __name__ == '__main__':
    main()