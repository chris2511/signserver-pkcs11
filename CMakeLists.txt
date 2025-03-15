cmake_minimum_required(VERSION 3.13.0)

project(keyutils-pkcs11
    VERSION 0.1.0
    DESCRIPTION "PKCS#11 key utility"
    LANGUAGES C
)

find_package(OpenSSL REQUIRED)

message(STATUS "Using Clang/GNU options")
add_compile_options(-Wall -Wextra -Wpedantic -Werror)
add_compile_options(-fmacro-prefix-map=${PROJECT_SOURCE_DIR}=.)

find_library(keyutils keyutils)

add_library(keyutils-pkcs11 MODULE
    pkcs11.c unavailable.c keyutil-pkcs11.h
    attr.c attr.h
    key.c key.h
    object.c object.h
    session.c session.h
    slot.c slot.h
    link.c link.h
    x509.c x509.h
)

target_link_libraries(keyutils-pkcs11 keyutils OpenSSL::Crypto)
