from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify
import uuid, base64, json, jwt, os

# format for a jwk
# kid uuid
# alg RS256
# kty RSA
# use sig
# n N value of public key encoded with base64
# e AQAB
# exp when it expires

# have public keys be a global variable
public_keys = {}

# generate the server through flask
app = Flask('jwks_server')

# fill public keys with what is stored in public_keys.json
def open_public_keys():
    global public_keys

    # have to check if there is json in there if there is none then just set the public keys to an empty object
    if os.path.getsize('public_keys.json') > 0:
        try:
            with open('public_keys.json', 'r') as file:
                public_keys = json.load(file)
                return
        except FileNotFoundError:
            pass
    else:
        public_keys = {}

# write new public key to public_keys.json
def write_public_keys():
    global public_keys

    with open('public_keys.json', 'w') as file:
        json.dump(public_keys, file)

# process the get request
@app.route('/.well-known/jwks.json')
def jwks():
    global public_keys

    # get current time
    cur_time = datetime.utcnow().timestamp()

    # create a list of acceptable keys
    keys = []

    # if the expiry is greater than the current time then it is valid and add it to keys
    # e is always AQAB
    for kid, key in public_keys.items():
        expiry = key.get('exp', 0)
        if expiry > cur_time:
            keys.append({
                'kid': kid,
                'alg': key['alg'],
                'kty': key['kty'],
                'use': key['use'],
                'n': key['n'],
                'e': 'AQAB',
                'exp': key['exp'],
            })

    return jsonify({"keys": keys})

# process the post request
@app.route('/auth', methods=['POST'])
def auth():
    # check if it is expired
    isExpired = request.args.get('expired') == 'true'

    # generate the private rsa key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # get the public key
    public_key = private_key.public_key()

    # encode the public key in base 64 url
    n_bytes = public_key.public_numbers().n.to_bytes(256, byteorder='big')
    n_b64url = base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode()

    # fill out the global variable public_keys
    open_public_keys()

    # generate kid as new uuid
    kid = str(uuid.uuid4())

    # generate expiry
    if isExpired:
        expiry = (datetime.utcnow() - timedelta(days=1)).timestamp()
    else:
        expiry = (datetime.utcnow() + timedelta(days=1)).timestamp()

    # add new entry into public keys
    # e is always AQAB
    public_keys[kid] = {
        'kid': kid,
        'alg': 'RS256',
        'kty': 'RSA',
        'use': 'sig',
        'n': n_b64url,
        'e': 'AQAB',
        'exp': expiry,
    }

    # write to the file
    write_public_keys()

    # store the result in a jwt token
    if not isExpired:
        token = jwt.encode({'username': 'user'}, private_key, headers = {'kid': kid, 'alg': 'RS256'})
    else:
        token = jwt.encode({'username': 'user', 'exp': expiry}, private_key, algorithm = 'RS256', headers = {'kid': kid})

    return token

# set the port to 8080 keeping it in debug is fine
# used by flask
if __name__ == '__main__':
    app.run(debug=True, port=8080)
