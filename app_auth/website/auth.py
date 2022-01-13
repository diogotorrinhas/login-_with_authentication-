from flask import Blueprint,render_template,request, redirect, url_for, make_response
from flask.helpers import flash
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from database.database import db
from flask_login import login_user, login_required, logout_user, current_user
from .views import set_headers
from time import time
from random import randint, choice
from .echap import generateChallenge, generateUAPResponse, generateAuthenticatorResponse, binResponse
import string
import hashlib

AUTHENDPOINT = 'http://127.0.0.1:5000/connect'
MAXROUNDS = 20
connections = {}
auth = Blueprint('auth', __name__, template_folder="templates/")

@auth.route('/login', methods=['GET'])
def login():
    return make_response(redirect('http://localhost:5050/login/' + AUTHENDPOINT))

@auth.route('/login_done', methods=['GET'])
def login_done():
    addr = request.remote_addr
    if addr in connections.keys() and 'token' in connections[addr].keys() and connections[addr]['login_done'] and request.args.get('token') == connections[addr]['token']:
        user = User.query.filter_by(email=connections[addr]['username']).first()
        login_user(user)
    connections.pop(addr)
    return make_response(redirect(url_for('views.home')))

@auth.route('/connect', methods=['POST'])
def connect():
    if request.is_json:
        data = request.json()
    else:
        data = request.form

    # Check if time exceeded (30s)
    if request.remote_addr in connections.keys():
        if time() - connections[request.remote_addr]['starttime'] >= 30:
            connections.pop(request.remote_addr)

    # If username is received, start authentication
    if 'username' in data.keys():
        return startAuth(data['username']) 
    elif ('bit' in data.keys()) and('uap_challenge' in data.keys()) and (request.remote_addr in connections.keys()):
        return checkAuth(data['bit'], data['uap_challenge'])
    elif ('bit' in data.keys()) and (request.remote_addr in connections.keys()):
        return checkAuth(data['bit'])
    elif ('success' in data.keys()) and (request.remote_addr in connections.keys()):
        return checkSuccess(data['success'])
    return {'error': 'data incorrect'}

def startAuth(username):
    # Get User object if user present in db
    user = User.query.filter_by(email=username).first()
    if not user:
        connection = {
                'username': username,
                'password': hashlib.sha256(randStr(12).encode('utf-8')).hexdigest(),
                'authenticator_challenge': generateChallenge(),
                'success': False,
                'rounds': 0,
                'starttime': time()
            }
    else:
        connection = {
                'username': username,
                'password': user.password,
                'authenticator_challenge': generateChallenge(),
                'success': True,
                'rounds': 0,
                'starttime': time()
        }

    connections[request.remote_addr] = connection
    return { 'authenticator_challenge': connection['authenticator_challenge'] }

def checkAuth(bit, uap_challenge=None):
    # Check if connection with addr was already established
    addr = request.remote_addr
    if addr not in connections.keys():
        return {'error': '...'}

    if uap_challenge != None:
        connections[addr]['uap_challenge'] = uap_challenge
        connections[addr]['uap_response'] = generateUAPResponse(
                connections[addr]['authenticator_challenge'],
                connections[addr]['uap_challenge'],
                connections[addr]['username'],
                connections[addr]['password']
        )
        connections[addr]['authenticator_response'] = generateAuthenticatorResponse(
                connections[addr]['password'],
                connections[addr]['uap_response'],
                connections[addr]['uap_challenge'],
                connections[addr]['authenticator_challenge'],
                connections[addr]['username']
        )
        connections[addr]['bin_uap'] = binResponse(connections[addr]['uap_response'], connections[addr]['username'])
        connections[addr]['bin_authenticator'] = binResponse(connections[addr]['authenticator_response'], connections[addr]['username'])

    if connections[addr]['success']:
        connections[addr]['success'] = verifyBit(connections[addr]['bin_uap'], bit, connections[addr]['rounds'])

    if not connections[addr]['success']:
        data = {'bit': randint(0,1) }
    else:
        data = {'bit': connections[addr]['bin_authenticator'][connections[addr]['rounds']] }
    
    connections[addr]['rounds'] += 1
    if connections[addr]['rounds'] >= MAXROUNDS:
        data['success'] = connections[addr]['success']
        #TODO: check if a response is received when auth_success is 0

    return data

# Generate a random string of ascii letters with len(str) = size
def randStr(size):
    return ''.join(choice(string.ascii_letters) for x in range(size))

def checkSuccess(success):
    # Check if connection with addr was already established
    addr = request.remote_addr
    if addr not in connections.keys():
        return {'error': '...'}

    if connections[addr]['success'] and success:
        connections[addr]['login_done'] = True
        connections[addr]['token'] = randStr(8)
        return {'redirect': request.host_url + url_for('auth.login_done'), 'token': connections[addr]['token'] }

    connections.pop(addr)
    return {'error': 'authentication failed'}

# Verify if bit received equals bit generated
def verifyBit(bin_response, bit, position):
    return bit == bin_response[position]

@auth.route('/logout')
@login_required	#nao conseguimos fazer logout a não ser que estejamos logados
def logout():
	logout_user()
	return redirect(url_for('views.home'))
