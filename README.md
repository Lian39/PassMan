# Password Manager
## Password Manager with vault

PassMan is a secure vault with your logins and passwords in it. This tool intended to manage all of your logins and passwords with ease. It's also has such features as secure password generator and passwords health check.

Complete list of options:

- -a : add a new entry into the vault
- -d : delete an entry from vault
- -g : get an entry from vault
- -ga : get all entries from vault
- -uu : update url
- -ul : update login
- -up : update password
- -gp : generate secure password
- -hc : check passwords health

## Examples:
### Adding a new entry into the vault:
```
python passman.py -a <url> <login> <password>
```
### Deleting an entry from vault:
```
python passman.py -d <url>
```
### Getting an entry from vault:
```
python passman.py -g <url>
```
### Getting all entries from vault:
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