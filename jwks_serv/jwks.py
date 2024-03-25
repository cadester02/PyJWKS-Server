from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, request, jsonify
import uuid, base64, json, jwt, os, sqlite3

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

conn = sqlite3.connect('totally_not_my_privateKeys.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )''')

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

def serialized_private_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption
    )

def fill_EmptyDB():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM keys")
    numRows = c.fetchone()[0]

    # if there are no rows generate and expired and an unexpired entry
    if numRows == 0:
        exp_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # make int because of the db
        exp_expiry = int((datetime.utcnow() - timedelta(days=1)).timestamp())

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        expiry = int((datetime.utcnow() + timedelta(days=1)).timestamp())

        c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", serialized_private_key(exp_private_key).decode(), exp_expiry)
        c.execute("INSERT INTO keys (key, exp) VALUES(?, ?)", serialized_private_key(private_key), expiry)

        conn.commit()
        conn.close()


# process the get request
@app.route('/.well-known/jwks.json')
def jwks():
    # get current time
    cur_time = datetime.utcnow().timestamp()

    c.execute("SELECT key FROM keys WHERE exp >= ?", cur_time)
    nonExpired_keys = []
    for row in c.fetchall():
        nonExpired_keys.append(serialization.load_pem_private_key(row[0].encode(), password=None))

    jwks = []
    for i, key in enumerate(nonExpired_keys):
        jwks.append({
            "kid": str(uuid.uuid4),
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": base64.urlsafe_b64encode(key.public_key().public_numbers().n.to_bytes(256, byteorder='big')).decode().rstrip('='),
            "e": "AQAB"
        })

    return jsonify(jwks)

    

# process the post request
@app.route('/auth', methods=['POST'])
def auth():
    # check if it is expired
    isExpired = request.args.get('expired') == 'true'

    fill_EmptyDB()
    
    curDate = datetime.utcnow().timestamp()

    if isExpired:
        c.execute("SELECT key FROM keys WHERE exp < ?", curDate)
        row = c.fetchone()
        if row:
            private_key = serialization.load_pem_private_key(row[0].encode(), password=None)
            token = jwt.encode({'username': 'user', 'password': 'password'}, private_key, algorithm='RS256', headers={'kid': str(uuid.uuid4)})
        else:
            token = "Error key not found"
    else:
        c.execute("SELECT key FROM keys WHERE exp >= ?", curDate)
        row = c.fetchone()
        if row:
            private_key = serialization.load_pem_private_key(row[0].encode(), password=None)
            token = jwt.encode({'username': 'user', 'password': 'password'}, private_key, algorithm='RS256', headers={'kid': str(uuid.uuid4)})
        else:
            token = "Error key not found"

    return token

# set the port to 8080 keeping it in debug is fine
# used by flask
if __name__ == '__main__':
    app.run(debug=True, port=8080)
