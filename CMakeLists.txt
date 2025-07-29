cmake_minimum_required(VERSION 3.13.0)

project(signserver-pkcs11
    VERSION 0.1.0
    DESCRIPTION "PKCS#11 library for Keyfactor SignServer"
    LANGUAGES C
)

find_package(OpenSSL REQUIRED)
find_library(INIPARSER NAMES iniparser)
find_path(INIPARSER_INCLUDE_DIR NAMES iniparser.h PATH_SUFFIXES iniparser)
include_directories(${INIPARSER_INCLUDE_DIR})

set(CMAKE_SHARED_MODULE_PREFIX "")
add_compile_options(-Wall -Wextra -Wpedantic -Werror -fvisibility=hidden)
add_compile_options(-fmacro-prefix-map=${PROJECT_SOURCE_DIR}=.)

add_library(signserver-pkcs11 MODULE
    pkcs11.c signserver-pkcs11.h
    slot.c slot.h
    attr.c attr.h
    object.c object.h
    key.c key.h
    session.c session.h
    storage.c storage.h
)

target_link_libraries(signserver-pkcs11 iniparser OpenSSL::Crypto)
