/*
 * isha.c
 *
 * A completely insecure and bad hashing algorithm, based loosely on
 * SHA-1 (which is itself no longer considered a good hashing
 * algorithm)
 *
 * Based on code for sha1 processing from Paul E. Jones, available at
 * https://www.packetizer.com/security/sha1/
 *
 * Optimization by Harshwardhan Singh, harshwardhan.singh@colorado.edu
 * Reference/Credit: Mukta Darekar and Taher Ujjainwala for
 * helping me with the code flow and working of the program
 */

#include "isha.h"
#include <string.h>

/*
 * circular shift macro
 */
#define ISHACircularShift(bits,word) \
  ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))

/*
 * Processes the next 512 bits of the message stored in the MBlock
 * array.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAProcessMessageBlock(ISHAContext *ctx)
{
	register uint32_t temp;
	register int t;
	register uint32_t A, B, C, D, E;

	A = ctx->MD[0];
	B = ctx->MD[1];
	C = ctx->MD[2];
	D = ctx->MD[3];
	E = ctx->MD[4];

	for(t = 0; t < 16; t++)
	{
		temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + ((((uint32_t) ctx->MBlock[t * 4]) << 24) |
				(((uint32_t) ctx->MBlock[t * 4 + 1]) << 16) | (((uint32_t) ctx->MBlock[t * 4 + 2]) << 8) |
				((uint32_t) ctx->MBlock[t * 4 + 3]));
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = ISHACircularShift(30,B);
		B = A;
		A = temp;
	}

	ctx->MD[0] += A;
	ctx->MD[1] += B;
	ctx->MD[2] += C;
	ctx->MD[3] += D;
	ctx->MD[4] += E;

	ctx->MB_Idx = 0;
}


/*
 * The message must be padded to an even 512 bits.  The first padding
 * bit must be a '1'.  The last 64 bits represent the length of the
 * original message.  All bits in between should be 0. This function
 * will pad the message according to those rules by filling the MBlock
 * array accordingly. It will also call ISHAProcessMessageBlock()
 * appropriately. When it returns, it can be assumed that the message
 * digest has been computed.
 *
 * Parameters:
 *   ctx         The ISHAContext (in/out)
 */
static void ISHAPadMessage(ISHAContext *ctx)
{
	/*
	 *  Check to see if the current message block is too small to hold
	 *  the initial padding bits and length.  If so, we will pad the
	 *  block, process it, and then continue padding into a second
	 *  block.
	 */
	if (ctx->MB_Idx > 55)
	{
		ctx->MBlock[ctx->MB_Idx++] = 0x80;
		memset(ctx->MBlock + ctx->MB_Idx,0,ISHA_BLOCKLEN - ctx->MB_Idx);

		ISHAProcessMessageBlock(ctx);

		memset(ctx->MBlock + ctx->MB_Idx,0,ISHA_BLOCKLEN-4 - ctx->MB_Idx); //sets '0' to MBlock from MBlock[MB_Idx] till (60-MB_Idx) bytes
	}
	else
	{
		ctx->MBlock[ctx->MB_Idx++] = 0x80;
		memset(ctx->MBlock + ctx->MB_Idx,0,ISHA_BLOCKLEN-4 - ctx->MB_Idx); //sets '0' to MBlock from MBlock[MB_Idx] till (60-MB_Idx) bytes
	}

	/*
	 *  Store the message length as the last 8 octets
	 */

	ctx->MBlock[60] = (ctx->message_len >> RSHIFT_24) & 0xFF;
	ctx->MBlock[61] = (ctx->message_len >> RSHIFT_16) & 0xFF;
	ctx->MBlock[62] = (ctx->message_len >> RSHIFT_8) & 0xFF;
	ctx->MBlock[63] = (ctx->message_len) & 0xFF;

	ISHAProcessMessageBlock(ctx);
}

void ISHAReset(ISHAContext *ctx)
{
	ctx->MB_Idx = 0;
	ctx->message_len=0;	//length of message in bits

	ctx->MD[0] = 0x67452301;
	ctx->MD[1] = 0xEFCDAB89;
	ctx->MD[2] = 0x98BADCFE;
	ctx->MD[3] = 0x10325476;
	ctx->MD[4] = 0xC3D2E1F0;

	ctx->Computed = 0;
	ctx->Corrupted = 0;
}


void ISHAResult(ISHAContext *ctx, uint8_t *digest_out)
{
	if (ctx->Corrupted)
	{
		return;
	}

	if (!ctx->Computed)
	{
		ISHAPadMessage(ctx);
		ctx->Computed = 1;
	}
/*
 * Description: used bswap32() for completing the task.
 */
	*((uint32_t *)(digest_out))=__builtin_bswap32(ctx->MD[0]);
	*((uint32_t *)(digest_out+DIGEST_4))=__builtin_bswap32(ctx->MD[1]);
	*((uint32_t *)(digest_out+DIGEST_8))=__builtin_bswap32(ctx->MD[2]);
	*((uint32_t *)(digest_out+DIGEST_12))=__builtin_bswap32(ctx->MD[3]);
	*((uint32_t *)(digest_out+DIGEST_16))=__builtin_bswap32(ctx->MD[4]);

	return;
}

/*
 * Reference/Credit: in collaboration with and guidance by Taher Ujjainwala,
 * worked together on tracing and discussed the ways of optimizing ISHAInput() function.
 */
void ISHAInput(ISHAContext *ctx, const uint8_t *message_array, size_t length)
{
	if (!length)
	{
		return;
	}

	if(length==ISHA_BLOCKLEN) 	//check if the message length is equal to ISHA_BLOCKLEN (64)
	{
		memcpy(ctx->MBlock+ctx->MB_Idx,message_array,ISHA_BLOCKLEN); //copies the data of message_array to the MBlock till ISHA_BLOCKLEN bytes
		ctx->message_len = ISHA_BLOCKLEN*CONVERT_TO_BITS; 			 //number of bits is stored in message length
		ctx->MB_Idx = ctx->MB_Idx + ISHA_BLOCKLEN; 		 			 //increments message_index by ISHA_BLOCKLEN i.e. 64 in this case
		ISHAProcessMessageBlock(ctx);
	}
	else
	{
		ctx->message_len = ctx->message_len + (length*CONVERT_TO_BITS); //increments message_length by length and stores the data in bits
		while(length--)
		{
			ctx->MBlock[ctx->MB_Idx++] = (*message_array & 0xFF);
			message_array++;
			if(ctx->MB_Idx==ISHA_BLOCKLEN)
			{
				ISHAProcessMessageBlock(ctx);
			}
		}
	}
}
