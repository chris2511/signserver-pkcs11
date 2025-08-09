# PKCS11 Library for Keyfactor Signserver PlainSigner

Supports EC and RSA private keys and alternatively can
make use of software keys.

Secure boot and code signing procedures for the Linux kernel,
U-Boot and other non-standard (PE/EXE, PDF, PKCS#7) mechanisms
in the secure boot chain, like first-stage bootloaders, usually
rely on PKCS#11 to perform the signatures.

If, on the other hand, you only have the
[Keyfactor SignServer](https://docs.keyfactor.com/signserver/latest/)
as HSM interface, then this is the middleware for you.

To reduce the difference between development builds (signed with local software keys)
and release builds (signed with official HSM-backed keys provided by the Keyfactor SignServer), this library also supports software keys.
The release build then only differs by the content of the INI file.

The workers and software keys are configured by an INI file. The object name is the
section name. A typical PKCS#11 URI looks like: `pkcs11:object=default-EC` for the default-EC section

## INI file configuration

The library is configured via an INI file, e.g. `signserver-pkcs11.ini`.
Each section defines a key/certificate source and connection parameters for a SignServer worker.
The keys are case-insensitive.

### Example

```ini
[default]
SignServer = true
Certificate = Signserver.pem
AuthCert = SignServer_Client.pfx
AuthPass = pass
WorkerName = MyPlainSigner
cka_id = 6789ABCD
url = https://192.168.1.1
VerifyPeer = false

[default-EC]
SignServer = true
Certificate = Signserver-signer00002.pem
AuthCert = SignServer_Client.pfx
AuthPass = pass
WorkerName = EcPlainSigner
url = https://nucci.tucht

[default-soft]
SignServer = true
Certificate = Gandalf_der_Graue.pem
```

### Field descriptions

- **SignServer**: Necessary to be set to true to be recognized as valid slot by
    signserver-pkcs11.so.
- **Certificate**: Path to the public certificate used by the SignServer for signing.
    Can be left empty for SignServer slots and must contain the unencrypted private key
    for software slots.
- **AuthCert**: Path to the PKCS#12 client certificate for TLS authentication to the SignServer
- **AuthPass**: Password for the PKCS#12 file.
- **WorkerName**: Name of the PlainSign worker in SignServer.
- **cka_id**: (Optional) PKCS#11 CKA\_ID for key selection.
- **url**: URL of the SignServer REST API endpoint.

You can define multiple sections for different key/certificate sources or workers.

# Configuration with environment variables

```
export SIGNSERVER_PKCS11_INI=signserver-pkcs11.ini
export SIGNSERVER_PKCS11_DEBUG=1
```

`SIGNSERVER_PKCS11_INI` points to the location of the configuration file
`SIGNSERVER_PKCS11_DEBUG` enables debugging:

 1) Nothing, not even fatal errors
 2) Errors, usually when returning other results than CKR\_OK
 3) Debugging
 4) More debugging

# OpenSSL with engine

## openssl.cnf

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

# OpenSSL with provider
You need to explicitly enable the default provider:
```
[openssl_init]
 providers = provider_sect

[provider_sect]
 default = default_sect

[default_sect]
 activate = 1
````
Install the PKCS#11 Provider and set PKCS11_PROVIDER_MODULE

```
$ openssl x509 -provider pkcs11 -in "pkcs11:object=default"
$ openssl pkey -provider pkcs11 -in "pkcs11:object=default" -pubin
```
