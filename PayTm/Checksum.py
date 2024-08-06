# pip install pycryptodome
import base64
import string
import random
import hashlib
from Crypto.Cipher import AES

IV = "@@@@&&&&####$$$$"
BLOCK_SIZE = 16

def __validate_key_length__(key):
    """Validate the length of the AES key."""
    if len(key) not in {16, 24, 32}:
        raise ValueError("Invalid AES key length. Must be 16, 24, or 32 bytes.")
    
def __pad_key__(key):
    """Pad or truncate the key to ensure it is 16, 24, or 32 bytes long."""
    return key.ljust(32)[:32]  # Ensure 32 bytes for AES    


def __id_generator__(size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
    """Generate a random string of a given size."""
    return ''.join(random.choice(chars) for _ in range(size))

def __get_param_string__(params):
    """Construct a parameter string from the dictionary."""
    params_string = []
    for key in sorted(params.keys()):
        if "|" in params[key]:
            raise ValueError("Invalid character '|' in parameter values.")
        value = params[key]
        params_string.append('' if value == 'null' else str(value))
    return '|'.join(params_string)

def __pad__(s):
    """Pad the string to be a multiple of BLOCK_SIZE using PKCS7."""
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def __unpad__(s):
    """Remove PKCS7 padding from the string."""
    return s[0:-ord(s[-1])]

def __encode__(to_encode, iv, key):
    """Encrypt and encode the string using AES in CBC mode."""
    to_encode = __pad__(to_encode)
    c = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    to_encode = c.encrypt(to_encode.encode('utf-8'))
    to_encode = base64.b64encode(to_encode)
    return to_encode.decode("UTF-8")

def __decode__(to_decode, iv, key):
    """Decode and decrypt the string using AES in CBC mode."""
    to_decode = base64.b64decode(to_decode)
    c = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    to_decode = c.decrypt(to_decode)
    to_decode = to_decode.decode()
    return __unpad__(to_decode)

def generate_checksum(param_dict, merchant_key, salt=None):
    """Generate a checksum for the given parameters and merchant key."""
    merchant_key = __pad_key__(merchant_key)  # Ensure the key is the correct length
    __validate_key_length__(merchant_key)
    params_string = __get_param_string__(param_dict)
    salt = salt if salt else __id_generator__(4)
    final_string = '%s|%s' % (params_string, salt)

    hasher = hashlib.sha256(final_string.encode())
    hash_string = hasher.hexdigest()
    hash_string += salt

    return __encode__(hash_string, IV, merchant_key)

def generate_refund_checksum(param_dict, merchant_key, salt=None):
    """Generate a refund checksum for the given parameters and merchant key."""
    for value in param_dict.values():
        if "|" in value:
            raise ValueError("Invalid character '|' in parameter values.")
    merchant_key = __pad_key__(merchant_key)  # Ensure the key is the correct length
    __validate_key_length__(merchant_key)
    params_string = __get_param_string__(param_dict)
    salt = salt if salt else __id_generator__(4)
    final_string = '%s|%s' % (params_string, salt)

    hasher = hashlib.sha256(final_string.encode())
    hash_string = hasher.hexdigest()
    hash_string += salt

    return __encode__(hash_string, IV, merchant_key)

def generate_checksum_by_str(param_str, merchant_key, salt=None):
    """Generate a checksum from a parameter string and merchant key."""
    merchant_key = __pad_key__(merchant_key)  # Ensure the key is the correct length
    __validate_key_length__(merchant_key)
    salt = salt if salt else __id_generator__(4)
    final_string = '%s|%s' % (param_str, salt)

    hasher = hashlib.sha256(final_string.encode())
    hash_string = hasher.hexdigest()
    hash_string += salt

    return __encode__(hash_string, IV, merchant_key)

def verify_checksum(param_dict, merchant_key, checksum):
    """Verify the checksum against the given parameters and merchant key."""
    if 'CHECKSUMHASH' in param_dict:
        param_dict.pop('CHECKSUMHASH')
    
    merchant_key = __pad_key__(merchant_key)  # Ensure the key is the correct length
    __validate_key_length__(merchant_key)
    paytm_hash = __decode__(checksum, IV, merchant_key)
    salt = paytm_hash[-4:]
    calculated_checksum = generate_checksum(param_dict, merchant_key, salt=salt)
    return calculated_checksum == checksum

def verify_checksum_by_str(param_str, merchant_key, checksum):
    """Verify the checksum against the given parameter string and merchant key."""
    merchant_key = __pad_key__(merchant_key)  # Ensure the key is the correct length
    __validate_key_length__(merchant_key)
    paytm_hash = __decode__(checksum, IV, merchant_key)
    salt = paytm_hash[-4:]
    calculated_checksum = generate_checksum_by_str(param_str, merchant_key, salt=salt)
    return calculated_checksum == checksum

if __name__ == "__main__":
    params = {
        "MID": "mid",
        "ORDER_ID": "order_id",
        "CUST_ID": "cust_id",
        "TXN_AMOUNT": "1",
        "CHANNEL_ID": "WEB",
        "INDUSTRY_TYPE_ID": "Retail",
        "WEBSITE": "xxxxxxxxxxx"
    }

    try:
        checksum = generate_checksum(params, '1234567890123456')  # Example key
        print("Generated checksum:", checksum)

        is_valid = verify_checksum(params, '1234567890123456', checksum)
        print("Checksum valid:", is_valid)
    except Exception as e:
        print(f"Error: {e}")
