#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

uint8_t * hex_to_uint8(const char* hex_str, size_t hex_len) {

    size_t uint8_len = hex_len / 2;
		uint8_t * uint8_str = (uint8_t *)malloc(uint8_len);
		memset(uint8_str, 0, uint8_len);
		size_t i = 0;

    while (i < hex_len) {
        char c = hex_str[i];
        int value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else
            return NULL;
        uint8_str[(i / 2)] += value << (((i + 1) % 2) * 4);
        i++;
    }

    return uint8_str;
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	//encode secret
	size_t hex_len = strlen(secret_hex);
	uint8_t * data = hex_to_uint8(secret_hex, hex_len);
	uint8_t secret[17];
	base32_encode(data, 20, secret, 16);
	secret[16] = '\0';
	// char * secret = "CI2FM6EQCI2FM6EQ";
	// printf("secret: %s\n",secret);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	char * otp_type[2] = {"hotp","totp"};
	char * otp_param[2] = {"counter=1","period=30"};
	int variableLength = strlen(accountName)+strlen(issuer);
	//len(otp)=4, len(secret)=16 ==> 20
	int invariableLength = 20+strlen("otpauth://")+strlen("?issuer=")+strlen("&secret=")+strlen("counter=1")+2;
	char * URI = (char *)malloc(variableLength+invariableLength);

	for (int i=0;i<2;i++){
		sprintf(URI, "otpauth://%s/%s?issuer=%s&secret=%s&%s",
			otp_type[i],
			accountName,
			issuer,
			(char *)secret,
			otp_param[i]
		);
		displayQRcode(URI);
	}

	return (0);
}
