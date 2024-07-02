# encrypt
openssl aes-256-cbc -e -in plain.txt -out cipher.txt -K '6879746B6579' -iv '99741C77C34A68F90D7276DA38AC33F7' -p -nosalt -base64
# decrypt
openssl aes-256-cbc -d -in cipher.txt -out decrypted.txt -K '6879746B6579' -iv '99741C77C34A68F90D7276DA38AC33F7' -p -nosalt -base64