cmake_minimum_required(VERSION 3.13.0)

project(keyutils-pkcs11
    VERSION 0.1.0
    DESCRIPTION "PKCS#11 key utility"
    LANGUAGES C
)
find_library(keyutils keyutils)

add_library(keyutils-pkcs11 MODULE pkcs11.c unavailable.c)
add_executable(testapp test.c)

target_link_libraries(testapp keyutils)
target_link_libraries(keyutils-pkcs11 keyutils)
