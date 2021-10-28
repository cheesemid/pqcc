#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

uint8_t *strtouint8ptr(char *nptr){
    int i, len = strlen(nptr);
    if (len % 2 != 0){
        return NULL;
    }
    uint8_t *bytearr = calloc(len/2, 1);
    uint8_t *bytearrcurr = bytearr;
    for (i = 0; i < len; i+=2){
        uint64_t conv;
        uint8_t *byteconv;
        char *tempstr = calloc(3, 1);
        *tempstr = *(nptr + i);
        *(tempstr + 1) = *(nptr + i + 1);
        *(tempstr + 2) = 0x00;
        conv = strtoul(tempstr, NULL, 16);
        byteconv = (uint8_t *)&conv;
        *bytearrcurr = *byteconv;
        free(tempstr);
        bytearrcurr++;
    }
    return bytearr;
}

char *uint8ptrtostr(int len, uint8_t *nptr){
    int i;
    char *out = calloc((len*2)+1, 1);
    char *currout = out;
    for (i = 0; i < len; i++){
        char *conv = calloc(3,1);
        sprintf(conv, "%02x", *nptr++);
        *currout++ = *conv;
        *currout++ = *(conv+1);
        free(conv);
    }
    return out;
}

// To test the program
// int main(int argc, char **argv){
//     if (argc >= 2) {
//         int i;
//         int len = strlen(argv[1]);
//         strtouint8ptr(argv[1]);
//         for (i = 0; i < len/2; i++){
//             printf("%02X ", *(bytearr + i));
//         }
//         printf("\n%d\n", len/2);
//     }
//     return 0;
// }