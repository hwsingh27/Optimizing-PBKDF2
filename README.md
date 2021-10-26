# PES-Assignment-5

# Optimization Steps
The following changes were made on the initial code to optimize <br/>

## void hmac_isha(....) <br/>
1) Used memcpy() and memset() in place loops used for copying and setting the data. <br/>
2) Used resgister keyword for while variable declaration -  . <br/>
  Registers are faster than memory to access, so the variables which are most frequently used in a C program can be put in registers using register keyword. <br/>
  The keyword register hints to compiler that a given variable can be put in a register. It's compiler's choice to put it in a register or not. (Resource: GeeksForGeeks)<br/><br/>
    - Previously <br/>
    
    size_t i;<br/>
    
    for (i=0; i<key_len; i++) <br/>
      keypad[i] = key[i]; <br/>
    for(i=key_len; i<ISHA_BLOCKLEN; i++) <br/>
      keypad[i] = 0x00; <br/>
      
   - Changes <br/>
   
    register size_t i;<br/>
   
    memcpy(keypad,key,key_len);<br/>
    memset(keypad+key_len,0x00,ISHA_BLOCKLEN);<br/>
    

## void F(....) <br/>
1) Used memcpy() in place loops used for copying the data to reduce the time. <br/>
2) Also used register while declaring the variables.<br/>
3) For loops were changed to while loops.<br/><br/>
    - Previously <br/>
   
    size_t i;<br/>
    
    for (i=0; i<salt_len; i++)<br/>
    saltplus[i] = salt[i];<br/>
    
    hmac_isha(pass, pass_len, saltplus, salt_len+4, temp);<br/>
    for (int i=0; i<ISHA_DIGESTLEN; i++)<br/>
        result[i] = temp[i];<br/>

    for (int j=1; j<iter; j++) {<br/>
        hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);<br/>
    for (int i=0; i<ISHA_DIGESTLEN; i++)<br/>
        result[i] ^= temp[i];<br/>
  }<br/><br/>
  
   - Changes <br/>
   
    register size_t i;<br/>
    
    memcpy( saltplus, salt, salt_len );<br/>
	  i = salt_len; <br/>
    
    hmac_isha(pass, pass_len, saltplus, salt_len+4, temp);<br/>
	  memcpy(result, temp, ISHA_DIGESTLEN);<br/>
    
    	register int j=1;<br/>
	    while(j<iter)<br/>
	    {<br/>
		      hmac_isha(pass, pass_len, temp, ISHA_DIGESTLEN, temp);<br/>
		      register int i=0;<br/>
		  while(i<ISHA_DIGESTLEN)<br/>
		  {<br/>
			    result[i] ^= temp[i];<br/>
			    i++;<br/>
		  }<br/>
		  j++;<br/>
	    }<br/><br/>
    
## void pbkdf2_hmac_isha(....) <br/>
1) Used memcpy() in place loops used for copying the data to reduce the time. <br/>
2) Also used register while declaring the variables.<br/><br/>
    - Previously <br/>
   
    int l = dkLen / ISHA_DIGESTLEN + 1;<br/>
    for (int i=0; i<l; i++) {<br/>
    F(pass, pass_len, salt, salt_len, iter, i+1, accumulator + i*ISHA_DIGESTLEN);<br/>
    }<br/>
    for (size_t i=0; i<dkLen; i++) {<br/>
    DK[i] = accumulator[i];<br/>
    }<br/><br/>
      
   - Changes <br/>
   	  
    register int l = dkLen / ISHA_DIGESTLEN + 1;<br/>

	  for (int i=0; i<l; i++) {<br/>
	    F(pass, pass_len, salt, salt_len, iter, i+1, accumulator + i*ISHA_DIGESTLEN);<br/>
	  }<br/>
	  memcpy(DK,accumulator,dkLen);<br/><br/>
    
## void ISHAProcessMessageBlock(....) <br/>
1) Merged two for loops into one and put W[t] in other loop that is also running 16 times. <br/>
2) Extra operations were removed while updating ctx->MD[0 to 5].<br/><br/>
    - Previously <br/>
   
     for(t = 0; t < 16; t++)<br/>
     {<br/>
        W[t] = ((uint32_t) ctx->MBlock[t * 4]) << 24;<br/>
        W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 1]) << 16;<br/>
        W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 2]) << 8;<br/>
        W[t] |= ((uint32_t) ctx->MBlock[t * 4 + 3]);<br/>
     }<br/>
     
      ctx->MD[0] = (ctx->MD[0] + A) & 0xFFFFFFFF;<br/>
      ctx->MD[1] = (ctx->MD[1] + B) & 0xFFFFFFFF;<br/>
      ctx->MD[2] = (ctx->MD[2] + C) & 0xFFFFFFFF;<br/>
      ctx->MD[3] = (ctx->MD[3] + D) & 0xFFFFFFFF;<br/>
      ctx->MD[4] = (ctx->MD[4] + E) & 0xFFFFFFFF;<br/><br/>
    
      
   - Changes <br/>
   	  for(t = 0; t < 16; t++)<br/>
	    {<br/>
		      temp = ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + ((((uint32_t) ctx->MBlock[t * 4]) << 24) |<br/>
				  (((uint32_t) ctx->MBlock[t * 4 + 1]) << 16) | (((uint32_t) ctx->MBlock[t * 4 + 2]) << 8) |<br/>
				  ((uint32_t) ctx->MBlock[t * 4 + 3]));<br/>
      		temp &= 0xFFFFFFFF;<br/>
		      E = D;<br/>
		      D = C;<br/>
		      C = ISHACircularShift(30,B);<br/>
		      B = A;<br/>
		      A = temp;<br/>
	     }<br/>
       
       ctx->MD[0] += A;<br/>
	     ctx->MD[1] += B;<br/>
	     ctx->MD[2] += C;<br/>
	     ctx->MD[3] += D;<br/>
	     ctx->MD[4] += E;<br/><br/>
       
## void ISHAPadMessage(....) <br/>
1) Used memset() in place loops used for passing a fixed value to reduce the time. <br/>
2) Reduced the number of instructions while putting the values from MBlock[56] to MBlock[64] because value of MBlock[56 to 59] will be '0'.<br/><br/>
    - Previously <br/>
   
    if (ctx->MB_Idx > 55)<br/>
    {<br/>
      ctx->MBlock[ctx->MB_Idx++] = 0x80;<br/>
      while(ctx->MB_Idx < 64)<br/>
    {<br/>
      ctx->MBlock[ctx->MB_Idx++] = 0;<br/>
    }<br/>

    ISHAProcessMessageBlock(ctx);<br/>

    while(ctx->MB_Idx < 56)<br/>
    {<br/>
      ctx->MBlock[ctx->MB_Idx++] = 0;<br/>
    }<br/>
    }<br/>
    else<br/>
    {<br/>
      ctx->MBlock[ctx->MB_Idx++] = 0x80;<br/>
      while(ctx->MB_Idx < 56)<br/>
    {<br/>
      ctx->MBlock[ctx->MB_Idx++] = 0;<br/>
    }<br/>
  }<br/>

  /*<br/>
   *  Store the message length as the last 8 octets<br/>
   */<br/>
      ctx->MBlock[56] = (ctx->Length_High >> 24) & 0xFF;<br/>
      ctx->MBlock[57] = (ctx->Length_High >> 16) & 0xFF;<br/>
      ctx->MBlock[58] = (ctx->Length_High >> 8) & 0xFF;<br/>
      ctx->MBlock[59] = (ctx->Length_High) & 0xFF;<br/>
      ctx->MBlock[60] = (ctx->Length_Low >> 24) & 0xFF;<br/>
      ctx->MBlock[61] = (ctx->Length_Low >> 16) & 0xFF;<br/>
      ctx->MBlock[62] = (ctx->Length_Low >> 8) & 0xFF;<br/>
      ctx->MBlock[63] = (ctx->Length_Low) & 0xFF;<br/><br/>
   
      
   - Changes <br/>
   	  
      	if (ctx->MB_Idx > 55)<br/>
	      {<br/>
		        ctx->MBlock[ctx->MB_Idx++] = 0x80;<br/>
		        memset(ctx->MBlock + ctx->MB_Idx,0,ISHA_BLOCKLEN - ctx->MB_Idx);<br/>

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
            
      
## void ISHAReset(....) <br/>
1) Removed Length_High and Length_Low for tracking the length of message, instead single variable message_len is used to keep the track of message length. <br/><br/>
    - Previously <br/>
  
      ctx->Length_Low  = 0;<br/>
      ctx->Length_High = 0;<br/><br/>
   
      
   - Changes <br/> 
      
      ctx->message_len=0;	//length of message in bits<br/><br/>
      
## void ISHAResult(....) <br/>
1) __builtin_bswap32() is used in place of the for loop, as it is an inbuilt function, it reduces the time significantly. <br/>
2) Created a macro bswap(32) to use in place of the builtin function, but that was not efficient as it was taking more time than the built-in function.<br/><br/>
    - Previously <br/>
   
     for (int i=0; i<20; i+=4) {<br/>
     digest_out[i]   = (ctx->MD[i/4] & 0xff000000) >> 24;<br/>
     digest_out[i+1] = (ctx->MD[i/4] & 0x00ff0000) >> 16;<br/>
     digest_out[i+2] = (ctx->MD[i/4] & 0x0000ff00) >> 8;<br/>
     digest_out[i+3] = (ctx->MD[i/4] & 0x000000ff);<br/>
  } <br/><br/>
      
   - Changes <br/>  
    
    	*((uint32_t *)(digest_out))=__builtin_bswap32(ctx->MD[0]);<br/>
	    *((uint32_t *)(digest_out+DIGEST_4))=__builtin_bswap32(ctx->MD[1]);<br/>
	    *((uint32_t *)(digest_out+DIGEST_8))=__builtin_bswap32(ctx->MD[2]);<br/>
	    *((uint32_t *)(digest_out+DIGEST_12))=__builtin_bswap32(ctx->MD[3]);<br/>
	    *((uint32_t *)(digest_out+DIGEST_16))=__builtin_bswap32(ctx->MD[4]);<br/><br/>
    
    

## void ISHAInput(....) <br/>
1) This function was changed as it had a loop that was iterating more than it was supposed to.  <br/>
2) Hence, a loop was used in such a way that when condition becomes true then it iterates only a single time instead of iterating the length times.<br/>
3) And after doing so, the parameters get changed accordingly.<br/><br/>

    - Previously <br/>
   while(length-- && !ctx->Corrupted)<br/>
  {<br/>
    ctx->MBlock[ctx->MB_Idx++] = (*message_array & 0xFF);<br/>

    ctx->Length_Low += 8;<br/>
    /* Force it to 32 bits */<br/>
    ctx->Length_Low &= 0xFFFFFFFF;<br/>
    if (ctx->Length_Low == 0)<br/>
    {<br/>
      ctx->Length_High++;<br/>
      /* Force it to 32 bits */<br/>
      ctx->Length_High &= 0xFFFFFFFF;<br/>
      if (ctx->Length_High == 0)<br/>
      {<br/>
        /* Message is too long */<br/>
        ctx->Corrupted = 1;<br/>
      }<br/>
    }<br/>

    if (ctx->MB_Idx == 64)<br/>
    {<br/>
      ISHAProcessMessageBlock(ctx);<br/>
    }<br/>

    message_array++;<br/>
    }<br/><br/>

      
   - Changes <br/> 

/*<br/>
 * Reference/Credit: in collaboration with and guidance by Taher Ujjainwala,<br/>
 * worked together on tracing and optimizing this specific function of ISHAInput().<br/>
 */<br/><br/>
if(length==ISHA_BLOCKLEN) 	//check if the message length is equal to ISHA_BLOCKLEN (64)<br>
	{<br>
		memcpy(ctx->MBlock+ctx->MB_Idx,message_array,ISHA_BLOCKLEN); //copies the data of message_array to the MBlock till ISHA_BLOCKLEN bytes<br>
		ctx->message_len = ISHA_BLOCKLEN*CONVERT_TO_BITS; 			 //number of bits is stored in message length<br>
		ctx->MB_Idx = ctx->MB_Idx + ISHA_BLOCKLEN; 		 			 //increments message_index by ISHA_BLOCKLEN i.e. 64 in this case<br>
		ISHAProcessMessageBlock(ctx);<br>
	}<br>
	else<br>
	{<br>
		ctx->message_len = ctx->message_len + (length*CONVERT_TO_BITS); //increments message_length by length and stores the data in bits<br>
		while(length--)<br>
		{<br>
			ctx->MBlock[ctx->MB_Idx++] = (*message_array & 0xFF);<br>
			message_array++;<br>
			if(ctx->MB_Idx==ISHA_BLOCKLEN)<br>
			{<br>
				ISHAProcessMessageBlock(ctx);<br>
			}<br>
		}<br>
	}<br><br/>
    
# Size .text Analysis 
    - Previously 
        -  (bytes) 

    - Updated 
        - 20,260 (bytes)

# Runtime Analysis 
    - Previously 
        - 8744 msec

    - Updated 
        - 2630 msec 
