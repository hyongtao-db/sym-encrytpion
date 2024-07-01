#include <stdio.h>
#include <string.h>
#include <stdint.h>


#include "aes.h"
#include "pkcs7_padding.c"

static void test_encrypt_cbc(void);


int main(void)
{
    int exit=0;

#if defined(AES256)
    printf("\nTesting AES256\n\n");
#else
    printf("You need to specify a symbol between AES128, AES192 or AES256. Exiting");
    return 0;
#endif

    test_encrypt_cbc();

    return exit;
}


static void test_encrypt_cbc(void)
{
    //Initialization Vector
    uint8_t iv[]  = { 0x99, 0x74, 0x1C, 0x77, 0xC3, 0x4A, 0x68, 0xF9, 0x0D, 0x72, 0x76, 0xDA, 0x38, 0xAC, 0x33, 0xF7 };
    // [153  116   28    119   195   74    104   249   13    114   118   218   56    172   51    247]
    // 0x99, 0x74, 0x1C, 0x77, 0xC3, 0x4A, 0x68, 0xF9, 0x0D, 0x72, 0x76, 0xDA, 0x38, 0xAC, 0x33, 0xF7

    uint8_t i;                               
    char* report = "helloworld";
    char* key = "hytkey";
    int dlen = strlen(report);
    int klen = strlen(key);
    
    printf("THE PLAIN TEXT STRING = ");
    for (i=0; i<dlen;i++){
        printf("%c", report[i]);
    }
    printf("\n");
    
   
    //Proper Length of report
    int dlenu = dlen;
    if (dlen % 16) {
        dlenu += 16 - (dlen % 16);
        printf("The original length of the STRING = %d and the length of the padded STRING = %d\n", dlen, dlenu);
    }
    
    //Proper length of key
    int klenu = klen;
    if (klen % 16) {
        klenu += 16 - (klen % 16);
        printf("The original length of the KEY = %d and the length of the padded KEY = %d\n", klen, klenu);
    }
    
    // Make the uint8_t arrays
    uint8_t hexarray[dlenu];
    uint8_t kexarray[klenu];
    
    // Initialize them with zeros
    memset( hexarray, 0, dlenu );
    memset( kexarray, 0, klenu );
    
    // Fill the uint8_t arrays
    for (i=0;i<dlen;i++) {
        hexarray[i] = (uint8_t)report[i];
    }
    for (i=0;i<klen;i++) {
        kexarray[i] = (uint8_t)key[i];
    }                           
  
    int reportPad = pkcs7_padding_pad_buffer( hexarray, dlen, sizeof(hexarray), 16 );
    int keyPad = pkcs7_padding_pad_buffer( kexarray, klen, sizeof(kexarray), 16 );
    
    printf("The padded STRING in hex is = ");
    for (i=0; i<dlenu;i++){
        printf("%02x ",hexarray[i]);
    }
    printf("\n");
    
    printf("The padded key in hex is = ");
    for (i=0; i<klenu;i++){
        printf("%02x ",kexarray[i]);
    }
    printf("\n");
    
    // In case you want to check if the padding is valid
    int valid = pkcs7_padding_valid( hexarray, dlen, sizeof(hexarray), 16 );
    int valid2 = pkcs7_padding_valid( kexarray, klen, sizeof(kexarray), 16 );
    printf("Is the pkcs7 padding valid report = %d  |  key = %d\n", valid, valid2);
    
    //start the encryption
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, kexarray, iv);
    
    // encrypt
    AES_CBC_encrypt_buffer(&ctx, hexarray, dlenu);
    printf("the encrypted STRING hex = ");
    for (i=0; i<dlenu;i++){
        printf("%02x ",hexarray[i]);
    }
    printf("\n");
    printf("the encrypted STRING = ");
    for (i=0; i<dlenu;i++){
        printf("%03d ",hexarray[i]);
    }
    // pay attention
    // C version: [166 112 231 138 172 039 177 158 231 166 094 082 003 098 028 067]
    // go version: [42 29 89 22 210 135 228 104 184 238 75 37 118 234 29 207]
    printf("\n");
        
    // reset the iv !! important to work!
    AES_ctx_set_iv(&ctx,iv);
    
    // start decryption
    AES_CBC_decrypt_buffer(&ctx, hexarray, dlenu);
    
    size_t actualDataLength = pkcs7_padding_data_length( hexarray, dlenu, 16);
    printf("The actual data length (without the padding) = %ld\n", actualDataLength);
    
    printf("the decrypted STRING in hex = ");
    for (i=0; i<actualDataLength;i++){
        printf("%02x ",hexarray[i]);
    }
    printf("\n");
}

/*
ciphertextBytes = [42 29 89 22 210 135 228 104 184 238 75 37 118 234 29 207]
ciphertext = FIOVSFWSQ7SGROHOJMSXN2Q5Z4

C part

the encrypted STRING hex = a6 70 e7 8a ac 27 b1 9e e7 a6 5e 52 03 62 1c 43 
the encrypted STRING = 166 112 231 138 172 039 177 158 231 166 094 082 003 098 028 067 
The actual data length (without the padding) = 10
the decrypted STRING in hex = 68 65 6c 6c 6f 77 6f 72 6c 64 
*/