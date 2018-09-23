# TLS Client Handshake Pure Python implementation #
This project is mainly used for demonstrating how tls handshake is performed for python programmers.    
Do not use this project in any production environment, it is just for education.    

# Supports #
TLSv1.1, TLSv1.2  
RSA, ECDHE-RSA, ECDHE-ECDSA key exchange  
AES CBC, GCM encryption  

# Requirements #
Python 3.6 (tested)  
pipenv  
cryptography  

# Installation #
setup your venv  
```
python -m venv .
source bin/activate (linux)
Scripts/activate (windows cmd)

pip install pipenv
pipenv install
```

# Usage #
python index.py <domain>  
for example,  
python index.py www.facebook.com  
To specify cipher
python index.py <domain> -c <cipher>  
for example,  
python index.py www.facebook.com -c AES256-SHA

# Todo #
TLS v1.3  
TLS v1.0 (low priority as it has already end of life)  
PSS Padding on signature algorithm  
Other Cipher suites such as DE  
http2  


# Contribution #
PR is welcome