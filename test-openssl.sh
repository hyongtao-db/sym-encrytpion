echo -n "helloworld" | openssl enc -e -aes-256-cbc -a -nosalt -pass pass:hytkey
echo -e
echo "WCuCCo+ohRklX4xMj+O9+g==" | openssl enc -d -aes-256-cbc -a -nosalt -pass pass:hytkey
echo -e
