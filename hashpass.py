import base64
import hmac
import json
from hashlib import sha256

class HashpassError(Exception):

    pass

class HashpassRecord:

    def __init__(self, label: str, salt: str, nospecials: bool, length: int, check: str):
        self.label = label
        self.salt = salt
        self.length = length
        self.nospecials = nospecials
        self.check = check

    def serialize(self) -> dict:
        return {'salt' : self.salt, 'nospecials' : self.nospecials, 'length': self.length, 'check': self.check}

    def update(self, salt, nospecials, length, check):
        self.salt = salt
        self.length = length
        self.nospecials = nospecials
        self.check = check

class HashpassRecordsPool:

    def __init__(self):
        self.is_updated = False
        self.records = {}

    def update(self, label, salt = '', nospecials = False, length = 0, check = ''):
        if label in self.records:
            current = self.records[label].serialize()
            if current['salt'] != salt or current['nospecials'] != nospecials or current['length'] != length:
                self.records[label].update(salt, nospecials, length, check)
                self.is_updated = True
        else:
            self.records[label] = HashpassRecord(label, salt, nospecials, length, check)
            self.is_updated = True

    def serialize(self):
        return {record: self.records[record].serialize() for record in self.records}

    def unserialize(self, serialized: dict):
        self.records = {}
        for label in serialized:
            self.records[label] = HashpassRecord(label, **serialized[label])

    def erase(self):
        self.records = {}
        self.is_updated = True

    def clear(self):
        self.records = {}
        self.is_updated = False

    def get_parameters(self, label):
        parameters = self.records[label].serialize()
        del parameters['check']
        return parameters

    def get_all_parameters(self):
        return {label : self.get_parameters(label) for label in self.records}

    def check(self, label, check) -> bool:
        if label in self.records:
            return check == self.records[label].check
        else:
            return True

class Hashpass:

    def __init__(self):
        self.pool = HashpassRecordsPool()
        self.records_file = None
    
    def load_records(self, records_file: str):
        self.records_file = records_file
        self.pool.clear()
        try:
            with open(self.records_file, 'r') as f:
                self.pool.unserialize(json.load(f))
        except:
            print('Failed to load records file. Erase it.')
            self.pool.erase()

    def get_records_parameters(self):
        return self.pool.get_all_parameters()

    def save_records(self):
        if self.records_file:
            with open(self.records_file, 'w') as f:
                json.dump(self.pool.serialize(), f, indent=4)

    def is_updated(self) -> bool:
        return (self.records_file != None) and (self.pool.is_updated)

    def auto_compute_password(self, master_secret, label: str):
        try:
            parameters = self.pool.get_parameters(label)
        except KeyError:
            raise HashpassError('Cannot auto-generate password, unknown label')
        return self.compute_password(master_secret=master_secret, label=label, **parameters)

    def compute_password(self, master_secret, label, salt = '', nospecials = False, length = 0):

        if len(salt) > 0:
            suffix = '|' + salt
        else:
            suffix = ''

        # Compute hash mac between master secret and label (website name, service name, ...)
        hash_mac = hmac.new(master_secret.encode('ascii'), (label + suffix).encode('ascii'), sha256).digest()

        # Derivate the hash mac to reduce hmac lookup risk
        hash_derivate = sha256(hash_mac).digest()

        # Compute base64
        password = base64.encodebytes(hash_derivate).decode('ascii')

        # Force special character. Add ! after number of character corresponding to most significant nibble of hmac
        offset = int(hash_mac[0] / 16)
        password = password[:offset] + '!' + password[offset:]

        # Remove specials characters
        if nospecials:
            password = ''.join([s for s in password if s in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"])

        # Keep maximum length
        if length > 0:
            password = password[:length]

        # Update pool with this update
        self.pool.update(label, salt, nospecials, length, password[0])

        # Check match with current pool
        if not self.pool.check(label, password[0]):
            raise HashpassError('Password checking detected mismatch. Verify your master password')

        return password