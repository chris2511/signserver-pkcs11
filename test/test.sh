#!/bin/sh

cd "$(dirname "$0")"
TMP_DIR="tmp"

BUILD_DIR="../build"
export OPENSSL_CONF=openssl.cnf
export SIGNSERVER_PKCS11_INI="signserver-pkcs11.ini"
export SIGNSERVER_PKCS11_DEBUG=2
# For the pkcs11-provider
export PKCS11_PROVIDER_MODULE="${BUILD_DIR}/signserver-pkcs11.so"
# For the libp11 Engine
export PKCS11_MODULE_PATH="$PKCS11_PROVIDER_MODULE"

set -e
rm -rf ${TMP_DIR}
mkdir -p ${TMP_DIR}

datafile="${TMP_DIR}/signdata.txt"
cat $SIGNSERVER_PKCS11_INI > ${datafile}

for obj in server-rsa server-4096 server-ec soft-rsa soft-ec; do
  openssl x509 -pubkey -nocert -in "${obj}.pem" -out "${TMP_DIR}/${obj}.pub"
  openssl x509 -in "${obj}.pem" -out "${TMP_DIR}/${obj}.crt" # Remove private key

  # Extracting certificate from the provider
  echo "Test Extracting certificate and pubkey from $obj provider"
  openssl x509 -provider pkcs11 -in pkcs11:object=${obj} -out "${TMP_DIR}/extracted-cert.${obj}"
  cmp -b ${TMP_DIR}/extracted-cert.${obj} ${TMP_DIR}/${obj}.crt

  openssl pkey -provider pkcs11 -pubin -in pkcs11:object=${obj} -out "${TMP_DIR}/extracted-pub.${obj}.pem"
  cmp -b ${TMP_DIR}/extracted-pub.${obj}.pem ${TMP_DIR}/${obj}.pub

  for alg in sha256 sha384 sha512; do
    echo "Testing $obj with $alg"
    # Sign the file with the provider
    openssl dgst -provider pkcs11 -sign "pkcs11:object=${obj}" -${alg} \
            -out ${TMP_DIR}/signature.${obj}.${alg} ${datafile}
    openssl dgst -verify "${TMP_DIR}/${obj}.pub" -${alg} \
            -signature ${TMP_DIR}/signature.${obj}.${alg} ${datafile}

    # Sign the file with the engine
    openssl dgst -engine pkcs11 -keyform ENGINE -sign "pkcs11:object=${obj}" -${alg} \
            -out ${TMP_DIR}/signature.${obj}.${alg} ${datafile}
    openssl dgst -verify "${TMP_DIR}/${obj}.pub" -${alg} \
            -signature ${TMP_DIR}/signature.${obj}.${alg} ${datafile}
  done
done

echo Try with C_Login
export SIGNSERVER_PKCS11_INI="signserver-pkcs11-login.ini"
openssl dgst -provider pkcs11 -sign "pkcs11:object=login-ec;pin-value=pass" -sha256 \
        -out ${TMP_DIR}/signature.login-ec ${datafile}
openssl dgst -verify "${TMP_DIR}/server-ec.pub" -sha256 \
        -signature ${TMP_DIR}/signature.login-ec ${datafile}

rm -rf ${TMP_DIR}
