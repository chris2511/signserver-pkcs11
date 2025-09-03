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
section name. A typical PKCS#11 URI looks like: `pkcs11:object=default-EC` for the default-EC section. All objects in the slot have the same name.
Applications like `openssl x509 ...` and `openssl pkey ...` will automatically pick
the right type, but `pkcs11-tool --slot 1 --type pubkey --label server-ec`
needs the type to pick the correct one.

## Build instructions and dependencies

### Dependencies

- CMake >= 3.13
- GCC or Clang
- OpenSSL development packages (libssl-dev)
- libcurl development packages (libcurl4-openssl-dev)
- iniparser library from https://github.com/ndevilla/iniparser (package 'libiniparser-dev')

### Build

```bash
git clone https://github.com/chris2511/signserver-pkcs11.git
cd signserver-pkcs11
cmake .
make
```

The module will be built as `signserver-pkcs11.so` in the `build/` directory.

Installation (optional):
```bash
sudo make install
```

See the file `CMakeLists.txt` for details about dependencies.

## INI file configuration

The library is configured via an INI file.
The default is `/etc/signserver-pkcs11.ini`.
Each section defines a key/certificate source and connection parameters for a SignServer worker.
The keys are case-insensitive.

### Login

The *AuthCert* password must either be empty or provided by the *AuthPass* variable or
it is absent in case of a software key.

Otherwise a C_Login is required with the correct AuthCert password.
In this case the *Certificate* option must be set to retrieve the certificate via PKCS#11

### Example

```ini
[default]
SignServer = true
# The library will perform a bogus signature to extract the certificate
# from the answer if this is unset
Certificate = Signserver.pem
# Authentication certificate when connecting to the sign server.
# Must be empty if no authentication is required
# Can be PFX, P12 or concatenated PEM
AuthCert = SignServer_Client.pfx
# The password of the PFX or PEM file above.
# Can also be provided during C_Login
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
url = https://192.168.1.1

[default-soft]
SignServer = true
# Certificate file must also contain the private key unencrypted to be usable as
# software key
Certificate = Gandalf_der_Graue.pem
```

### Field descriptions

- **SignServer**: Necessary to be set to true to be recognized as valid slot by
    signserver-pkcs11.so.
- **Certificate**: Path to the public certificate used by the SignServer for signing.
    Can be left empty for SignServer slots and must additionally contain the unencrypted private key
    for software slots.
- **AuthCert**: Path to the PKCS#12 or PEM+key client certificate for TLS authentication to the SignServer
- **AuthPass**: Password for the PKCS#12 file or the private key in the PEM file or must be provided via C_Login
- **WorkerName**: Name of the PlainSign worker in SignServer.
- **cka_id**: (Optional) PKCS#11 CKA\_ID for key selection.
- **url**: URL of the SignServer. This library uses the REST API.

You can define multiple sections for different key/certificate sources or workers.

## Configuration with environment variables

```bash
export SIGNSERVER_PKCS11_INI=signserver-pkcs11.ini
export SIGNSERVER_PKCS11_DEBUG=1
```

`SIGNSERVER_PKCS11_INI` points to the location of the configuration file

`SIGNSERVER_PKCS11_DEBUG` enables debugging:

 0) Nothing, not even fatal errors (default when unset)
 1) Errors, usually when returning other results than CKR\_OK
 2) Informational messages
 3) Debugging
 4) More debugging

# OpenSSL with engine

## openssl.cnf

```INI
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

## OpenSSL with provider

You need to explicitly enable the default provider:

```INI
[openssl_init]
 providers = provider_sect

[provider_sect]
 default = default_sect

[default_sect]
 activate = 1
```

Install the PKCS#11 Provider and set PKCS11_PROVIDER_MODULE

```bash
$ openssl x509 -provider pkcs11 -in "pkcs11:object=default"
$ openssl pkey -provider pkcs11 -in "pkcs11:object=default" -pubin
```
