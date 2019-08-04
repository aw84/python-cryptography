# Create key pair

Two key pairs are needed. One for Alice:

 ```python
import getpass
from helper.AsymetricKey import generate_key, save_key_pair
key_pair = generate_key()
password = getpass.getpass()
save_key_pair(key_pair, password, 'Alice')
```

Do this same for Bob:

```python
import getpass
from helper.AsymetricKey import generate_key, save_key_pair
key_pair = generate_key()
password = getpass.getpass()
save_key_pair(key_pair, password, 'Bob')
```

# Encrypt, decrypt

## Encrypt message for Bob 

```python
public_key = read_public_key('Bob_public.pem')
(aes_key_enc, ciphertext) = encrypt(public_key, b"abc")
```

Now `aes_key_enc` and `ciphertext` can be send over transmission channel.

## Decrypt message for Bob

```python
import getpass
password = getpass.getpass()
key = read_private_key('Bob_private.pem', password.encode())
msg = decrypt(key, aes_key_enc, ciphertext)
```