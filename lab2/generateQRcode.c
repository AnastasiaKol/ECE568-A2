#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

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

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	char * otp = "hotp";
	int variableLength = strlen(otp)+strlen(accountName)+strlen(issuer)+strlen(secret_hex);
	int invariableLength = strlen("otpauth://")+strlen("?issuer=")+strlen("&secret=")+strlen("counter=1")+4;
	// char * URI = malloc(variableLength+invariableLength);
	// sprintf(URI, "otpauth://%s/%s?issuer=%s&secret=%s&%s",
	// 	otp,
	// 	accountName,
	// 	issuer,
	// 	secret_hex,
	// 	otp=="hotp" ? "counter=1" : "period=30"
	// );
	char URI[100] = "";
	// strcat(URI,"otpauth://");
	strcpy(strcpy(strcpy(strcpy(strcpy(strcpy(strcpy(strcpy(strcpy(strcpy(strcpy(
		URI,"otpauth://"),
		otp),
		"/"),
		accountName),
		"?issuer="),
		issuer),
		"&secret="),
		secret_hex),
		"&"),
		otp=="hotp" ? "counter=1" : "period=30"),
		"\0");
	printf("URI: %s", URI);

	// displayQRcode("otpauth://testing");

	return (0);
}
