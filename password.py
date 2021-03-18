import base64
import sys
import hmac
from hashlib import sha256
from getpass import getpass

if len(sys.argv) < 2:
    print('usage: {} <label> [<salt>]'.format(sys.argv[0]))
    print('')
    print('arguments:')
    print('label      Name of the website / service / device to generate a password for (ex: facebook, iphone, samsung, ...)')
    print('salt       Optional variable parameter, to periodically renew the password (ex: 2020, first, ...)')
    sys.exit(1)

# Retrieve provided label from command line
label = sys.argv[1]

# Retrieve salt
if len(sys.argv) > 2:
    salt = '|' + sys.argv[2]    # Salt separator is |
else:
    salt = ''

# Get master secret
master_secret = getpass('Please enter you master secret: ')

# Compute hash mac between master secret and label (website name, service name, ...)
hash_mac = hmac.new(master_secret.encode('ascii'), (label + salt).encode('ascii'), sha256).digest()

# Derivate the hash mac to reduce hmac lookup risk
hash_derivate = sha256(hash_mac).digest()

# Compute base64
password = base64.encodebytes(hash_derivate).decode('ascii')

# Force special character. Add ! after number of character corresponding to most significant nibble of hmac
offset = int(hash_mac[0] / 16)
password = password[:offset] + '!' + password[offset:]

# Output password
print('\nYou password for {} is:'.format(label))
print(password)
