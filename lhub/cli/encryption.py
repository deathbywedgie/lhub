import os
import rsa
import base64
from .. import exceptions

# https://stuvel.eu/python-rsa-doc/usage.html#generating-keys


class Encryption:
    public_default = ".lhub.pub"
    private_default = ".lhub.pem"

    def __init__(self, key_location, private_key_name=None, pub_file_name=None):
        if not os.path.exists(key_location):
            raise IOError(f"Key location does not exist: {key_location}")
        self.key_location = key_location

        self.private_key_path = os.path.join(
            self.key_location,
            private_key_name.strip() if private_key_name else self.private_default
        )
        self.public_key_path = os.path.join(
            key_location,
            pub_file_name.strip() if pub_file_name else self.public_default
        )

        self._public_key = None
        self.__private_key = None
        self.load_keys()

    def load_keys(self):
        # If no existing keys are found stored at the expected location, generate new ones
        if not os.path.exists(self.private_key_path) and not os.path.exists(self.public_key_path):
            self._public_key, self.__private_key = rsa.newkeys(4096)
            with open(self.public_key_path, "w+") as _key_file:
                _key_file.write(self._public_key.save_pkcs1().decode())
            with open(self.private_key_path, "w+") as _key_file:
                _key_file.write(self.__private_key.save_pkcs1().decode())
            return

        if not os.path.exists(self.private_key_path):
            raise exceptions.EncryptionKeyError(f"Found public key ({self.public_key_path}) but could not find private key ({self.private_key_path})")
        if not os.path.exists(self.public_key_path):
            raise exceptions.EncryptionKeyError(f"Found private key ({self.private_key_path}) but could not find public key ({self.public_key_path})")

        with open(self.public_key_path, mode='rb') as _key_file:
            _public_key_text = _key_file.read()
        with open(self.private_key_path, mode='rb') as _key_file:
            _private_key_text = _key_file.read()
        self._public_key = rsa.PublicKey.load_pkcs1(_public_key_text)
        self.__private_key = rsa.PrivateKey.load_pkcs1(_private_key_text)
        return

    def encrypt_string(self, var_str):
        _var_bytes = var_str.encode()
        _var_encrypted = rsa.encrypt(_var_bytes, self._public_key)
        _var_encoded = base64.b64encode(_var_encrypted)
        return _var_encoded.decode()

    def decrypt_string(self, var_str):
        _var_bytes = var_str.encode()
        _var_decoded = base64.b64decode(_var_bytes)
        _var_decrypted = rsa.decrypt(_var_decoded, self.__private_key)
        return _var_decrypted.decode()
