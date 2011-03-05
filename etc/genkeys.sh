# generate a 2048-bit RSA private key
openssl genrsa -out ${1}_private_key.pem 1024
# convert private Key to PKCS#8 format (so Java can read it)
openssl pkcs8 -topk8 -inform PEM -outform DER -in ${1}_private_key.pem -out ${1}_private_key.der -nocrypt
# output public key portion in DER format (so Java can read it)
openssl rsa -in ${1}_private_key.pem -pubout -outform DER -out ${1}_public_key.der