# TLS Client Handshake Pure Python implementation #
This project is mainly used for demonstrating how tls handshake is performed for python programmers.    
Do not use this project in any production environment, it is just for education.    

# Supports #
TLSv1.1, TLSv1.2  
RSA, ECDHE-RSA, ECDHE-ECDSA key exchange  
AES CBC, GCM encryption  
SSLKEYLOGFILE

# Requirements #
Python 3.6 (tested)  
pipenv  
cryptography  

# Installation #
*venv*  
```
python -m venv .
source bin/activate (linux)
Scripts/activate (windows cmd)

pip install pipenv
pipenv install
# or you can install cryptography directly without pipenv

python index.py www.google.com
```

*pipenv*
```
pipenv install
pipenv run python index.py google.com
```

# Usage #
python index.py <domain>  
for example,  
python index.py www.facebook.com  
To specify cipher  
python index.py <domain> -c <cipher>  
for example,  
python index.py www.facebook.com -c AES256-SHA

cat <<EOF | python index.py -c ECDHE-ECDSA-AES256-GCM-SHA384 -   
www.facebook.com  
www.google.com   
EOF  

cat hosts.txt | python index.py -

# Todo #
TLS v1.3  
TLS v1.0 (low priority as its life has already ended)  
PSS Padding on signature algorithm  
Other Cipher suites such as DE  
http2  


# Contribution #
PR is welcome

# RSA key exchange algorithm
When RSA is used for server authentication and key exchange, a 48-byte pre_master_secret  
is generated by the client, encrypted under the server's public key, and sent to the server.  
The server uses its private key to decrypt the pre_master_secret.  Both parties then  
convert the pre_master_secret into the master_secret.

# ECDHE-RSA / ECDHE-ECDSA Algorithm
### Client Hello
Suggest Cipher Suites
### Server Hello
Agree on ECDHE-RSA / ECDHE-ECDSA.  
Server generates its ec key pair and sends the ec public key to the client along with the signature made by the server's private key which the public counterpart could be found in the server's digital certificate.  
### Client Finish
Client verifies the ec public key with the rsa / ec public key in the server's digital certificate.  
Client uses the ec public key and generates its own ec key pair in exchange for the pre master secret.  
Client sends its ec public key to the server.  
Client generates the master secret with the pre master secret and having shared randoms.  
Client starts sending encrypted data.  
### Server Finish
Server receives the client's ec public key  
Server uses the client's ec public key and the server private key in exchange for the same pre master secret.  
Server generates the master secret with the pre master secret and having shared randoms.  
Server decrypts the request with the master secret.  
