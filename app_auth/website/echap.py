from Crypto.Cipher import AES
import hashlib
import random
import string

# generate random challenge to perform authentication
def generateChallenge():
    randstr = ''.join(random.choice(string.ascii_letters + string.punctuation) for x in range(32))
    challenge = hashlib.sha256(randstr.encode('utf-8'))
    return challenge.hexdigest()

# Generate UAP response to server based on both challenges (received and created), username and password
def generateUAPResponse(authenticator_challenge, uap_challenge, username, password):
    challenge = challengeHash(uap_challenge, authenticator_challenge, username)
    password_hash = passwordHash(password)
    response = challengeResponse(challenge, password_hash)
    return response

# Create hash with both challenges and username
def challengeHash(uap_challenge, authenticator_challenge, username):
    context = hashlib.sha256()
    context.update(uap_challenge.encode('utf-8'))
    context.update(authenticator_challenge.encode('utf-8'))
    context.update(username.encode('utf-8'))
    digest = context.hexdigest()
    return digest[:32]

# Create password hash
def passwordHash(password):
    context = hashlib.sha256()
    context.update(password.encode('utf-8'))
    return context.hexdigest()

# create response to challenge
def challengeResponse(challenge, password_hash):
    response = aesEncrypt(challenge, password_hash[:32])
    response += aesEncrypt(challenge, password_hash[32:])
    return response

# Encrypt with aes a message (clear) with a given key in ECB mode
def aesEncrypt(clear, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    ciphertext = cipher.encrypt(clear.encode('utf-8'))
    return ciphertext.hex()

# Get random integer between 0 and 255 based on the username
# Collisions not important, only used to define start of binary verification
def intUsernameBased(username):
    context = hashlib.md5()
    context.update(username.encode('utf-8'))
    digest = context.hexdigest()
    number = int(digest[10:12],16)
    return number

# Generate authenticator response to uap based on both challenges, uap response, password and username
def generateAuthenticatorResponse(password, uap_response, uap_challenge, authenticator_challenge, username):
    # "Magic" constants used in response generation
    magic1 = [ # Len = 39
                0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
                0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
                0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
                0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74
            ]
    magic2 = [ # Len = 41
                0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
                0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
                0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
                0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
                0x6E
            ]
    # Generate a hash of password hash
    password_hash_hash = passwordHash(passwordHash(password))
    
    context = hashlib.sha512()
    context.update(password_hash_hash.encode('utf-8'))
    context.update(uap_response.encode('utf-8'))
    context.update(bytes(magic1))
    digest = context.digest()

    challenge = challengeHash(uap_challenge, authenticator_challenge, username)

    context = hashlib.sha512()
    context.update(digest)
    context.update(challenge.encode('utf-8'))
    context.update(bytes(magic2))
    digest = context.hexdigest()

    return digest

# generate binary word with length 256 bits, to perform bit by bit verification
def binResponse(response, username):
    bin_response = bin(int(response, 16))[2:]
    for _ in range(len(bin_response), 512): bin_response = '0' + bin_response
    based_int = intUsernameBased(username)
    return bin_response[based_int:based_int+256]

