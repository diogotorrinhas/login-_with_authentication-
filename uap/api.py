from flask import Flask, request, render_template, jsonify, redirect, make_response, url_for, abort
from uap import uap, checkMasterPassword, randStr, getCredentials, writeCredentials
from flask.helpers import flash
import sys

app = Flask(__name__)
endpoints = {}

@app.route('/login/<path:endpoint>', methods=['GET'])
def login(endpoint):
    if endpoint not in endpoints.values():
        shortener = randStr(8)
        while shortener in endpoints.keys(): shortener = randStr(8)
        endpoints[shortener] = endpoint
    else:
        for key, value in endpoints.items():
            if value == endpoint:
                shortener = key
                break

    return make_response(redirect('/' + shortener))

@app.route('/<string:shortener>', methods=['GET','POST'])
def connect(shortener):
    # Check if credentials for DNS are stored in DBFILE='credentials.json' 
    if shortener not in endpoints.keys():
        return abort(404)
    if request.method == 'GET':
        try:
            username, password = getCredentials(endpoints[shortener])
        except:
            username, password = None, None
        return make_response(render_template('authenticate.html', url=endpoints[shortener], username=username, password=password))

    username = request.form['username']
    password = request.form['password']
    endpoint = endpoints[shortener]
    data = uap(endpoint, 'api_key', username, password)  
    if 'redirect' not in data.keys():
        flash('Authentication failed: ' + data['status'], category='error')
        return make_response(redirect('/'+shortener))
    
    # Save credentials if authentication was successful
    if 'save' in request.form.keys():
        writeCredentials(endpoint,username,password)

    return make_response(redirect(data['redirect']))


def startApp():
    app.config.from_object('config.Config')
    app.run(host='127.0.0.1', port='5050', debug=False)


if __name__ == "__main__":
    # Check master password
    if not checkMasterPassword():
        sys.exit(2)
    startApp()
