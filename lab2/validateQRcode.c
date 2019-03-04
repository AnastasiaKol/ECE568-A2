#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "lib/sha1.h"

char * hex_to_binary(const char * hex_str, size_t hex_len) {

	size_t binary_len = hex_len * 4 +1;
	char * binary_str = (char *)malloc(binary_len);
	memset(binary_str, 0, binary_len);
  int i = 0;

  /* Extract first digit and find binary of each hex digit */
  for(i=0; i<hex_len; i++) {
    switch(hex_str[i]) {
      case '0':
        strcat(binary_str, "0000");
        break;
      case '1':
        strcat(binary_str, "0001");
        break;
      case '2':
        strcat(binary_str, "0010");
        break;
      case '3':
        strcat(binary_str, "0011");
        break;
      case '4':
        strcat(binary_str, "0100");
        break;
      case '5':
        strcat(binary_str, "0101");
        break;
      case '6':
        strcat(binary_str, "0110");
        break;
      case '7':
        strcat(binary_str, "0111");
        break;
      case '8':
        strcat(binary_str, "1000");
        break;
      case '9':
        strcat(binary_str, "1001");
        break;
      case 'a':
      case 'A':
        strcat(binary_str, "1010");
        break;
      case 'b':
      case 'B':
        strcat(binary_str, "1011");
        break;
      case 'c':
      case 'C':
        strcat(binary_str, "1100");
        break;
      case 'd':
      case 'D':
        strcat(binary_str, "1101");
        break;
      case 'e':
      case 'E':
        strcat(binary_str, "1110");
        break;
      case 'f':
      case 'F':
        strcat(binary_str, "1111");
        break;
      default:
        return NULL;
    }
  }
	// strcat(binary_str, "\0");

	return binary_str;
}

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

void xor(const char * k, char * pad) {
	for (int i=0; i<strlen(pad); i++){
		if (k[i]==pad[i]){
			pad[i] = '0';
		}
		else{
			pad[i] = '1';
		}
	}
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	// initialize opad, ipad, k and M
	char opad[128] = "36";
	char * p = opad;
	// printf("opad: %s\n", opad);
	for (int i=0; i<127; i++){
		strcat(p,"36");
	}
	size_t opad_len = strlen(opad);
	uint8_t * binary_opad = hex_to_uint8(opad, opad_len);
	// printf("opad: %s\n", opad);
	char ipad[128] = "5c";
	p = ipad;
	for (int i=0; i<127; i++){
		strcat(p, "5c");
	}
	size_t ipad_len = strlen(ipad);
	uint8_t * binary_ipad = hex_to_uint8(ipad, ipad_len);
	// printf("ipad: %s\n", ipad);
	size_t hex_len = strlen(secret_hex);
	uint8_t * secret = hex_to_uint8(secret_hex, hex_len);
	// printf("Length binary_str before: %lu\n", strlen(binary_str));
	// printf("Length binary_str after: %lu\n", strlen(binary_str));
	char * counter = (char *)malloc(1);
	strcat(counter,"1");

	// first hash round
	// printf("Binary str: %s\n\n", binary_str);
	// printf("ipad str: %s\n\n", ipad);
	uint8_t ipad_xor = int(secret)^int(binary_ipad);
	// printf("xor str: %s\n", ipad);
	SHA1_INFO ctx;
	uint8_t inner_sha[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, (uint8_t *)ipad_xor, strlen(ipad_xor));
	sha1_update(&ctx, (uint8_t *)counter, strlen(counter));
	sha1_final(&ctx, inner_sha);
	printf("inner_sha: %s\n", inner_sha);

	// second hash round
	// xor(binary_str, opad);
	// uint8_t outer_sha[SHA1_DIGEST_LENGTH];
	// sha1_update(&ctx, (uint8_t *)opad, strlen(opad));
	// sha1_update(&ctx, inner_sha, strlen((char *)inner_sha));
	// sha1_final(&ctx, outer_sha);
	//
	// printf("HMAC = %s\n", outer_sha);

	return (0);
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	size_t hex_len = strlen(secret_hex);
	char * binary_str = hex_to_binary(secret_hex, hex_len);
	printf("Hexadecimal number = %s\n", secret_hex);
  printf("Binary number = %s\n", binary_str);

	return (0);
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	validateHOTP(secret_hex, HOTP_value);

	// printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
	// 	secret_hex,
	// 	HOTP_value,
	// 	validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
	// 	TOTP_value,
	// 	validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
