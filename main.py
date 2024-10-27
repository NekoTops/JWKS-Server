# JWKS server that utilizes an sqlite database to store private keys for later retrevial.
# Functions produced or modified in part with ChatGPT have been labled below
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

# Set host defaults
hostName = "localhost"
serverPort = 8080

# Database setup
db_name = "totally_not_my_privateKeys.db"

# start database
############### Begin Database  Function Code ###############
# Connect DB and make query cursor
def init_db():  # produced in part with ChatGPT
    conn = sqlite3.connect("totally_not_my_privateKeys.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS keys (
                        kid INTEGER PRIMARY KEY AUTOINCREMENT,
                        key BLOB NOT NULL,
                        exp INTEGER NOT NULL
                    )''')
    conn.commit()
    conn.close()

# Store a new key in the database
def store_key(private_key, exp):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO keys (key, exp) VALUES (?, ?)''', (private_key, exp))
    conn.commit()
    conn.close()

# Retrieve all active keys
def get_all_keys(include_expired=False):  # produced in part with ChatGPT
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    current_time = int(datetime.datetime.utcnow().timestamp())
    if include_expired:
        cursor.execute("SELECT kid, key FROM keys ORDER BY exp DESC")
    else:
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp DESC", (current_time,))
    rows = cursor.fetchall()
    conn.close()
    return rows

# Retrieve the latest key, with an option to include expired keys
def get_latest_key(include_expired=True):  # produced in part with ChatGPT
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    current_time = int(datetime.datetime.utcnow().timestamp())
    if include_expired:
        cursor.execute("SELECT kid, key, exp FROM keys ORDER BY exp DESC LIMIT 1")
    else:
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1", (current_time,))
    row = cursor.fetchone()
    conn.close()
    return row if row else None

# Retrieve the latest expired key
def get_latest_expired_key():  # produced in part with ChatGPT
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    current_time = int(datetime.datetime.utcnow().timestamp())
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (current_time,))
    row = cursor.fetchone()
    conn.close()
    return row if row else None

# Generate a new RSA key, store it in the database with an expiration time
def generate_and_store_key(expiration_hours):  # produced in part with ChatGPT
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=expiration_hours)).timestamp())
    store_key(pem, exp)
    return pem, key
############### End Database Code ################ 

# Start the database and generate an initial key
init_db()
pem, private_key = generate_and_store_key(expiration_hours=1)  # 1-hour valid key
expired_pem, expired_key = generate_and_store_key(expiration_hours=-1)  # Immediately expired key

# Convert an integer to a Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    # Reject all responses except GET and POST
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return
    
    def do_POST(self): # modified in part with ChatGPT
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Get the latest key or expired key based on request
            if 'expired' in params:
                print("getting expired key")
                key_data = get_latest_expired_key()
            else:
                key_data = get_latest_key()
            
            if not key_data:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Error: No valid key found in database")
                return
            
            kid, key_data, exp = key_data  # Unpack the returned tuple
            headers = {
                "kid": str(kid)
            }
            token_payload = {
                "user": "username",
                "exp": exp
            }
            encoded_jwt = jwt.encode(token_payload, key_data, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self): # modified in part with ChatGPT
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            keys = {"keys": []}
            for kid, key_data in get_all_keys():
                # Load the key and get its public components
                private_key = serialization.load_pem_private_key(key_data, password=None)
                numbers = private_key.public_key().public_numbers()

                # Append each key's public components to the keys list
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })

            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

# Start server
if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
