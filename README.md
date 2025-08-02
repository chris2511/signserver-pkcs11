# PKCS11 Library for Keyfactor Signserver PlainSigner

This is work in progress
Supports EC / RSA

```
export SIGNSERVER\_PKCS11\_INI=signserver-pkcs11.ini
export SIGNSERVER\_PKCS11\_DEBUG=1
```

# Openssl with engine

## openssl.cn

```
[openssl_init]
 providers = provider_sect
 engines=engine_section

[engine_section]
 pkcs11 = pkcs11_section

[pkcs11_section]
 engine_id = pkcs11
 dynamic_path = /usr/lib/x86_64-linux-gnu/engines-3/libpkcs11.so
 MODULE_PATH = /usr/lib/x86_64-linux-gnu/signserver-pkcs11.so
```

openssl pkey -engine pkcs11 -inform ENGINE -pubin -in "pkcs11:object=default-ec"
openssl dgst -engine pkcs11 -keyform ENGINE -sign "pkcs11:object=default" -out signature.bin -sha256

# Openssl with provider
Need to explicitly enable the default provider
´´´
[openssl_init]
 providers = provider_sect

[provider_sect]
 default = default_sect

[default_sect]
 activate = 1
````
Install the PKCX11 Provider and set PKCS11_PROVIDER_MODULE

```
$ openssl x509 -provider pkcs11 -in "pkcs11:object=default"
$ openssl pkey -provider pkcs11 -in "pkcs11:object=default" -pubin
```
