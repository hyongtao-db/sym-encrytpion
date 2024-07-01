# golang version
``` bash
go run main.go
```

# C version
Please refer to https://erev0s.com/blog/tiny-aes-cbc-mode-pkcs7-padding-written-c/
```bash
make test
```

# Comparation
C version encrypted result in bytes
```bash
[166 112 231 138 172 039 177 158 231 166 094 082 003 098 028 067]
```
go version encrypted result in bytes
```bash
[42 29 89 22 210 135 228 104 184 238 75 37 118 234 29 207]
```