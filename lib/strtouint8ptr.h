#ifndef STRTOUINT8PTR_H
#define STRTOUINT8PTR_H

#include <stdint.h>

uint8_t *strtouint8ptr(char *nptr);
char *uint8ptrtostr(int len, uint8_t *nptr);

#endif /* ifndef STRTOUINT8PTR_H */