#include <stdio.h>
#include <keyutils.h>


int scanner_cb(key_serial_t parent, key_serial_t key, char *desc,
               int desc_len, void *data)
{
    const char *n = data;
    printf("parent(%s): %d, key: %d, desc: %s\n", n, parent, key, desc);
    return 1;
}

int main()
{
    long r = recursive_key_scan(KEY_SPEC_USER_KEYRING, scanner_cb, "GoGoGo");
    printf("recursive_key_scan @u: %ld\n", r);
    r = recursive_key_scan(KEY_SPEC_SESSION_KEYRING, scanner_cb, "GoGoGo");
    printf("recursive_key_scan @S: %ld\n", r);
    return 0;
}
