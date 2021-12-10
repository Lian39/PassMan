import unittest
from passman import *
settings = parse_config()
db_host, db_name, db_user = settings[::]

master_password = "MyMasterPassword"
salt = b"mysalt"
url = "google.com"
login = "mylogin"
password = "mypassword"

conn = connect(db_host, db_name, db_user, master_password)

class DataBaseTest(unittest.TestCase):
    def test_get_and_add_item(self):
        table_names = get_table_names(conn)
        create_vault(conn, table_names)
        add_item(conn, url, login, encrypt_password(salt, password, master_password))
        self.assertEqual(get_item(conn, url, salt, master_password), [['google.com', 'mylogin', 'mypassword']])
        delete_vault(conn, table_names)

    def test_get_all_items(self):
        table_names = get_table_names(conn)
        create_vault(conn, table_names)
        add_item(conn, url, login, encrypt_password(salt, password, master_password))
        self.assertEqual(get_all_items(conn, salt, master_password), [['google.com', 'mylogin', 'mypassword']])
        delete_vault(conn, table_names)

    def test_delete_item(self):
        table_names = get_table_names(conn)
        create_vault(conn, table_names)
        add_item(conn, url, login, encrypt_password(salt, password, master_password))
        delete_item(conn, url)
        self.assertEqual(get_item(conn, url, salt, master_password), [])
        delete_vault(conn, table_names)

    def test_update_url(self):
        table_names = get_table_names(conn)
        create_vault(conn, table_names)
        update_url(conn, 'gmail.com', url)
        self.assertEqual(get_item(conn, 'gmail.com', salt, master_password), [['gmail.com', 'mylogin', 'mynewpassword']])
        delete_vault(conn, table_names)

    def test_update_login(self):
        table_names = get_table_names(conn)
        create_vault(conn, table_names)
        update_login(conn, url, 'mynewlogin')
        self.assertEqual(get_item(conn, url, salt, master_password), [['google.com', 'mynewlogin', 'mypassword']])
        delete_vault(conn, table_names)

    def test_update_passsword(self):
        table_names = get_table_names(conn)
        create_vault(conn, table_names)
        add_item(conn, url, login, encrypt_password(salt, password, master_password))
        update_password(conn, url, encrypt_password(salt, 'mynewpassword', master_password))
        self.assertEqual(get_item(conn, url, salt, master_password), [['google.com', 'mylogin', 'mynewpassword']])
        delete_vault(conn, table_names)


if __name__=='__main__':
    unittest.main()