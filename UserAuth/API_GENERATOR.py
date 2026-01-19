import secrets
import string

#I will go with a length of 32 of randomness
secure_hex_token = secrets.token_hex(32)

#Url safe token
secrets_hex_urlsafe = secrets.token_urlsafe(32)

#for a strong, complex password/secret
alphabet = string.ascii_letters + string.digits + string.punctuation 
strong_password = ''.join(secrets.choice(alphabet) for i in range(24))


print(f"Hex Token: {secure_hex_token}")
print(f"urlsafe Hex Token: {secrets_hex_urlsafe}")
print(f"strong password: {strong_password}")

