/*
 * pbkdf2.c
 *
 * A perfectly legitimate implementation of HMAC and PBKDF2, but based
 * on the "ISHA" insecure and bad hashing algorithm.
 *
 * Author: Howdy Pierce, howdy.pierce@colorado.edu
 *
 * Optimization by Harshwardhan Singh, harshwardhan.singh@colorado.edu
 * Reference/Credit: Mukta Darekar and Taher Ujjainwala for
 * for helping me with the code flow.
 */

#include <assert.h>
#include <string.h>
#include "isha.h"
#include "pbkdf2.h"

/*
 * See function description in pbkdf2.h
 */
void hmac_isha(const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t *digest)
{
	uint8_t ipad[ISHA_BLOCKLEN];
	uint8_t opad[ISHA_BLOCKLEN];
	uint8_t keypad[ISHA_BLOCKLEN];
	uint8_t inner_digest[ISHA_DIGESTLEN];
	register size_t i;
	ISHAContext ctx;

	if (key_len > ISHA_BLOCKLEN)
	{
		// If key_len > ISHA_BLOCKLEN reset it to key=ISHA(key)
		ISHAReset(&ctx);
		ISHAInput(&ctx, key, key_len);
		ISHAResult(&ctx, keypad);
	}

    // key_len <= ISHA_BLOCKLEN; copy key into keypad, zero pad the result
    memcpy(keypad,key,key_len);
    memset(keypad+key_len,0x00,ISHA_BLOCKLEN);

    // XOR key into ipad and opad
    for (i=0; i<ISHA_BLOCKLEN; i++)
    {
    	ipad[i] = keypad[i] ^ 0x36;
    	opad[i] = keypad[i] ^ 0x5c;
    }

    // Perform inner ISHA
    ISHAReset(&ctx);
    ISHAInput(&ctx, ipad, ISHA_BLOCKLEN);
    ISHAInput(&ctx, msg, msg_len);
    ISHAResult(&ctx, inner_digest);

    // perform outer ISHA
    ISHAReset(&ctx);
    ISHAInput(&ctx, opad, ISHA_BLOCKLEN);
    ISHAInput(&ctx, inner_digest, ISHA_DIGESTLEN);
    ISHAResult(&ctx, digest);
}

/*
 * Implements the F function as defined in RFC 8018 section 5.2
 *
 * Parameters:
 *   pass      The password
 *   pass_len  length of pass
 *   salt      The salt
 *   salt_len  length of salt
 *   iter      The iteration count ("c" in RFC 8018)
 *   blkidx    the block index ("i" in RFC 8018)
 *   result    The result, which is ISHA_DIGESTLEN bytes long
 *
 * Returns:
 *   The result of computing the F function, in result
 */
static void F(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len,
    int iter, unsigned int blkidx, uint8_t *result)
{

	uint8_t temp[ISHA_DIGESTLEN];
	uint8_t saltplus[32]; //value changed from 2048 to 32, 20388 vs 20260 and time 2680 vs 2630msec
	register size_t i;
	assert(salt_len + 4 <= sizeof(saltplus));

	memcpy( saltplus, salt, salt_len );
	i = salt_len;

	// append blkidx in 4 bytes big endian
	saltplus[i] = (blkidx & 0xff000000) >> RSHIFT_24;
	saltplus[i+1] = (blkidx & 0x00ff0000) >> RSHIFT_16;
	saltplus[i+2] = (blkidx & 0x0000ff00) >> RSHIFT_8;
	saltplus[i+3] = (blkidx & 0x000000ff);

	hmac_isha(pass, pass_len, saltplus, salt_len+4, temp);
	memcpy(result, temp, ISHA_DIGESTLEN);

	register int j=1;
	while(j<iter)
	{
		hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);
		register int i=0;
		while(i<ISHA_DIGESTLEN)
		{
			result[i] ^= temp[i];
			i++;
		}
		j++;
	}
}

/*
 * See function description in pbkdf2.h
 */
void pbkdf2_hmac_isha(const uint8_t *pass, size_t pass_len,
    const uint8_t *salt, size_t salt_len, int iter, size_t dkLen, uint8_t *DK)
{
	  uint8_t accumulator[2560];
	  assert(dkLen < sizeof(accumulator));

	  register int l = dkLen / ISHA_DIGESTLEN + 1;

	  for (int i=0; i<l; i++) {
	    F(pass, pass_len, salt, salt_len, iter, i+1, accumulator + i*ISHA_DIGESTLEN);
	  }
	  memcpy(DK,accumulator,dkLen);
}
