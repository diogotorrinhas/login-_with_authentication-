from echap import generateChallenge, generateUAPResponse, generateAuthenticatorResponse, binResponse
from werkzeug.security import generate_password_hash, check_password_hash
from requests.structures import CaseInsensitiveDict
from cryptography.fernet import Fernet
from getpass import getpass
import requests
import asyncio
import hashlib
import random
import string
import base64
import json
import sys

ACCESSTOKEN = None
CREDTYPE = ['dns', 'username', 'password']
DBFILE = 'credentials.json'
ROUNDS = 20

# Generate a random string of ascii letters with len(str) = size
def randStr(size):
    return ''.join(random.choice(string.ascii_letters) for x in range(size))

# Get and check if masterpassword inserted is correct
def checkMasterPassword():
    global MASTERPASSWORD
    # Get masterpassword from user
    try:
        with open(DBFILE, 'r') as json_file:
            db = json.load(json_file)
    except:
        db = {}

    if 'master_password' in db.keys():
        MASTERPASSWORD = getpass('Please insert master password:')
        if not check_password_hash(db['master_password'], MASTERPASSWORD):
            print('Master password inserted is incorrect!')
            return False
        return check_password_hash(db['master_password'], MASTERPASSWORD)
    else:
        print('Master password not defined yet!')     
        p1 = getpass('Please add master password:')
        p2 = getpass('Please confirm master password:')
        if p1 != p2:
            print('Passwords are diferent!')
            return False

        MASTERPASSWORD = p1
        db= {
            'master_password': generate_password_hash(MASTERPASSWORD),
            'credentials': {}
        }

        # Write to file
        with open(DBFILE, 'w', encoding='utf-8') as f:
            json.dump(db, f, ensure_ascii=False, indent=4)
        
        return True

# Cipher credentials to store in DBFILE='credentials.json'
def cipherCred(cred, cred_type):
    assert MASTERPASSWORD != None
    # Get key for encryption
    key = MASTERPASSWORD.encode('utf-8')
    while len(key) < 32: key+=MASTERPASSWORD.encode('utf-8')
    key = base64.urlsafe_b64encode(key[:32])
    # Generate fernet encryptor
    fernet = Fernet(key)
    # Generate random salt
    salt = randStr(random.randint(5,20))
    # Data to encrypt
    data = (salt + '$' + cred).encode('utf-8')
    # Encrypted token
    token = fernet.encrypt(data)
    return token.decode('utf-8')

# decipher credentials to be used in authentication protocol 
def decipherCred(ccred, cred_type):
    assert MASTERPASSWORD != None
    # Get key for encryption
    key = MASTERPASSWORD.encode('utf-8')
    while len(key) < 32: key+=MASTERPASSWORD.encode('utf-8')
    key = base64.urlsafe_b64encode(key[:32])
    # Generate fernet encryptor
    fernet = Fernet(key)
    # Decrypted data
    data = fernet.decrypt(ccred.encode('utf-8')).decode('utf-8')
    # Remove salt
    data = data[data.find('$')+1:]
    return data

def writeCredentials(dns,username,password):
    with open(DBFILE, 'r') as json_file:
        db = json.load(json_file)

    db2 = {
        'master_password': db['master_password'],
        'credentials': {
            cipherCred(dns, 'dns'): {
                'username': cipherCred(username, 'username'),
                'password': cipherCred(password, 'password')

            }
        }
    }
    db2['credentials'].update(db['credentials'])

    # Write to file
    with open(DBFILE, 'w', encoding='utf-8') as f:
        json.dump(db2, f, ensure_ascii=False, indent=4)

# Get list of ciphered dns present in DBFILE='credentials.json'
def getDnsList():
    with open(DBFILE, 'r') as json_file:
        db = json.load(json_file)
    # Get deciphered dns stored
    dns_list = []
    for cdns in db['credentials'].keys():
        dns_list.append(decipherCred(cdns, 'dns'))
    return dns_list

# Get username for cdns stored in DBFILE='credentials.json'
def getUsername(cdns):
    with open(DBFILE, 'r') as json_file:
        db = json.load(json_file)
    cusername = db['credentials'][cdns]['username']
    return decipherCred(cusername, 'username')

# Get password for cdns stored in DBFILE='credentials.json'
def getPassword(cdns):
    with open(DBFILE, 'r') as json_file:
        db = json.load(json_file)
    cpassword = db['credentials'][cdns]['password']
    return decipherCred(cpassword, 'password')

# Get credentials from 'credentials.json'
# Send error message if they're not stored
def getCredentials(dns):
    # Get list of stored dns
    dns_list = getDnsList()

    if dns not in dns_list:
        #TODO: raise exception
        raise Exception('getCredentials: ERROR: Given dns not stored in the database!')

    # Get ciphered dns
    idx = dns_list.index(dns)
    with open(DBFILE, 'r') as json_file:
        l = json.load(json_file)['credentials']
        cdns = list(l.keys())[idx]

    username = getUsername(cdns)
    password = getPassword(cdns)
    return username, password
    
# First step of authentication:
#   Establish connection with the server
#   making a http get request to the dns given
#   and receive the authenticator challenge
# return: authentication challenge
def getAuthenticatorChallenge(session, api_key, dns, username):
    # Get authentication token to establish connection with the server
    # data = { 'key': api_key }
    # auth_message = session.post(dns, data=data)
    
    # Check if connection was established successfully
    # if 'access_token' not in auth_message.keys():
    #     raise Exception('getAuthenticatorChallenge: ERROR: API KEY is wrong')
    
    #TODO: check if is needed
    # ACCESSTOKEN = auth_message['access_token']
    
    # Create http headers
    # headers = CaseInsensitiveDict()
    # headers['Accept'] = 'application/json'
    # headers['Authorization'] = f'Bearer {ACCESSTOKEN}'
   
    # Make request to start authentication protocol
    data = { 'username': username }
    auth_message = session.post(dns, data=data) #, headers=headers)
    # return authenticator challenge
    return auth_message.json()['authenticator_challenge']

# send data (bits or/and uap challenge) to the authenticator
# returns bit to be verified and success message in case authentication ended
def sendAuthenticatorData(session, dns, data):
    # Create http headers
    # headers = CaseInsensitiveDict()
    # headers['Accept'] = 'application/json'
    # headers['Authorization'] = f'Bearer {ACCESSTOKEN}'

    # Send data to the authenticator
    auth_message = session.post(dns, data=data) #, headers=headers)
    
    # return bit and success (Always None except in the last message)
    if 'success' not in auth_message.json().keys(): return auth_message.json()['bit'], None
    return auth_message.json()['bit'], auth_message.json()['success']

# Send success bit to the authenticator
# In case both success a redirection to the service is returned
# Otherwise, the return value should be ignored
def sendAuthenticatorSuccess(session, dns, success):
    # Create http headers
    # headers = CaseInsensitiveDict()
    # headers['Accept'] = 'application/json'
    # headers['Authorization'] = f'Bearer {ACCESSTOKEN}'
    
    # data to send
    data = {'success': success}

    # Send success to the autenticator
    auth_message = session.post(dns, data=data) #, headers=headers)

    # return redirection (or failure)
    return auth_message

# Verify if bit received equals bit generated
def verifyBit(bin_response, bit, position):
    return bit == bin_response[position]

# Main function to run authentication protocol with server
def authenticate(session, api_key, dns, username, password):
    # Get authenticator challenge
    authenticator_challenge = getAuthenticatorChallenge(session, api_key, dns, username)
    # Generate uap challenge
    uap_challenge = generateChallenge()
    # Generate uap response to authenticator
    uap_response = generateUAPResponse(authenticator_challenge, uap_challenge, username, password)
    # Generate authenticator response
    authenticator_response = generateAuthenticatorResponse(password, uap_response, uap_challenge, authenticator_challenge, username)
    # Generate binary words to use in protocol
    bin_uap = binResponse(uap_response, username)
    bin_authenticator = binResponse(authenticator_response, username)

    # Send bit and challenge to the authenticator 
    data = {'bit': bin_uap[0], 'uap_challenge': uap_challenge }
    bit, _ = sendAuthenticatorData(session,dns,data)
    
    # Verify if bit received was correct
    uap_success = verifyBit(bin_authenticator, bit, 0)

    # Keep track of number of bits sent to authenticator
    bits_sent = 1 

    authenticator_success = None
    while authenticator_success == None:
        # Verify if authentication has been successful
        # if it was not successful, continue the verification with random bits
        if not uap_success: data = { 'bit': random.randint(0,1) }
        else: 
            data = {'bit': bin_uap[bits_sent] }

        # send data to the authenticator
        bit, authenticator_success = sendAuthenticatorData(session,dns,data)
        # update uap_success and bits_sent if it was successful until now
        if uap_success:
            uap_success = verifyBit(bin_authenticator, bit, bits_sent)
            bits_sent += 1
        # check if authenticator is requesting too much information (possible rogue)
        if bits_sent > 40: return {'status': 'failed at uap: Authenticator requested too many bits'}

    # if authentication was not successful, send success=0 to authenticator
    if (not uap_success) or (bits_sent < ROUNDS):
        sendAuthenticatorSuccess(session,dns,0)
        return {'status': f'failed at uap: bit {bits_sent-1}'}

    # if authentication failed at authenticator return status
    if not authenticator_success: return {'status' : 'failed at authenticator'}

    auth_message = sendAuthenticatorSuccess(session,dns,1)
    return {
        'status': 'success',
        'redirect': auth_message.json()['redirect'] + '?token=' + auth_message.json()['token']
    }

# Establish connection
# will only connect if credentials are stored in DBFILE='credentials.json'
def uap(dns, api_key, username, password):
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    if username == None or password == None:
        return { 'status': 'failed at uap: error reading credentials' }

    # Start a request session and run the authentication protocol
    try:
        with requests.Session() as session:
            data = authenticate(session, api_key, dns, username, password)
    except:
        data = {'status': 'error: somehting went wrong'}
    
    return data 
