# Password Manager
## Password Manager with vault

PassMan is a secure vault with your logins and passwords in it. This tool is intended to manage all of your logins and passwords with ease. It also has such features as secure password generator and passwords health check.

Complete list of options:

- -a : add a new item into the vault
- -d : delete an item from vault
- -g : get an item from vault
- -ga : get all items from vault
- -uu : update url
- -ul : update login
- -up : update password
- -gp : generate secure password
- -hc : check passwords health
- -i : import items
- e : export items

## Examples:
### Adding a new item into the vault:
```
python passman.py -a <url> <login> <password>
```
### Deleting an item from vault:
```
python passman.py -d <url>
```
### Getting an item from vault:
```
python passman.py -g <url>
```
### Getting all items from vault:
```
python passman.py -ga
```
### Updating url:
```
python passman.py -uu <old_url> <new_url>
```
### Updating login:
```
python passman.py -ul <url> <new_login>
```
### Updating password:
```
python passman.py -up <url> <new_password>
```
### Generating secure password:
```
python passman.py -gp <length>
```
### Checking passwords health:
```
python passman.py -hc
```
### Importing items from a csv file:
```
pytohn passman.py -i <path_to_csv_file>
```
### Exporting items to a csv file:
```
pytohn passman.py -i <path_to_csv_file>
```
## Note!
To use this Password Manager, you have to download PostgreSQL4 first!