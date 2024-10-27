# JWST Server in python.
## Overview
Simple JWKS Server that:
- Utilizes a Restful API structure
- Serves public keys linked to unique Key IDs(kid)
- Expires dated Keys ID's
- Verifies JSON Web Tokens(JWTs)
## Requirements
- Cryptography version: 43.0.1
- Pyjwt version:  2.8.0
## Diretions
1. Run main.py and the server will start
2. Open your favorite browser and go to "http://localhost:8080" to connect to the server
