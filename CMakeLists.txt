cmake_minimum_required(VERSION 3.13.0)

project(keyutils-pkcs11
    VERSION 0.1.0
    DESCRIPTION "PKCS#11 key utility"
    LANGUAGES C
)

find_package(OpenSSL REQUIRED)
find_library(INIPARSER NAMES iniparser)
find_path(INIPARSER_INCLUDE_DIR NAMES iniparser.h PATH_SUFFIXES iniparser)
include_directories(${INIPARSER_INCLUDE_DIR})

add_compile_options(-Wall -Wextra -Wpedantic -Werror -fvisibility=hidden)
add_compile_options(-fmacro-prefix-map=${PROJECT_SOURCE_DIR}=.)

add_library(keyutils-pkcs11 MODULE
    pkcs11.c signserver-pkcs11.h
    slot.c slot.h
    attr.c attr.h
    key.c key.h
    object.c object.h
    session.c session.h
    x509.c x509.h
    storage.c storage.h
)

target_link_libraries(keyutils-pkcs11 iniparser OpenSSL::Crypto)
