 #!/bin/sh

NAME="$1"
KEYRING="$2"
FILE="$2"

id="$(openssl < "$FILE" pkcs8 -topk8 -outform DER -nocrypt | keyctl padd asymmetric "priv:$NAME" "$KEYRING")"
keyctl setperm "$id" 0x3f3f0000
id="$(openssl < "$FILE" x509 -outform DER | keyctl padd asymmetric "pub:$NAME" "$KEYRING")"
keyctl setperm "$id" 0x3f3f0000
id="$(openssl < "$FILE" x509 -outform DER | keyctl padd user "x509:$NAME" "$KEYRING")"
keyctl setperm "$id" 0x3f3f0000
