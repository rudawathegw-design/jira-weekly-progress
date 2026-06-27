import hashlib, getpass, sys

password = sys.argv[1] if len(sys.argv) > 1 else getpass.getpass("Password: ")
h = hashlib.sha256(password.encode()).hexdigest()
print(h)
