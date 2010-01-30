/*********************************************************************************
 * Name: Base64
 * Description:
 *
 * This file holds the functions that handle the base 64 encoding and decoding.
 *
 * Date  : 15th February 2009
 * Author: Peter Antoine. 
 *
 * Copyright 2009 (c) Peter Antoine
 * Released under the Artistic Licence 2.0.
 * 
 * (See http://opensource.org/licenses/artistic-license-2.0.php)
 **********************************************************************************/

static const char encoding_string[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char decoded_byte[256] = {	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3e,0x00,0x00,0x00,0x3f,
										0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
										0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x00,0x00,0x00,0x00,0x00,
										0x00,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
										0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

/*------------------------------------------------------------* 
 * This function will convert the input into base64 encoding.
 * The function will convert up to the number of bytes that
 * will fit into the output buffer.
 *
 * The function will return the number of byte from the input 
 * buffer that was encoded.
 *
 * It will truncate the length of the input buffer to a multiple
 * of four bytes. If the input buffer exhausts before the output
 * buffer is filled the buffer will be padded to a multiple of 
 * four.
 *
 *	    +--------+--------+--------+--------+
 *	    | byte 1 | byte 2 | byte 3 | byte 4 |
 *      +--------+--------+--------+--------+
 * input:  aaaaaa   aabbbb   bbbbcc   cccccc
 *------------------------------------------------------------*/
int	encode_base64(	unsigned char*	output,
					unsigned int	output_size,
					unsigned char*	input,
					unsigned int 	input_size)
{
	unsigned int	bytes_encoded = 0;
	unsigned int	max_bytes = output_size & ~(0x03);
	unsigned int	start = 0;

	if (max_bytes > 0)
	{
		/* do the conversion */
		while((input_size - start) > 2 && bytes_encoded < max_bytes)
		{
			output[bytes_encoded]   = encoding_string[(input[start] >> 2)];
			output[bytes_encoded+1] = encoding_string[((input[start] & 0x03) << 4) | ((input[start+1] & 0xf0) >> 4)];
			output[bytes_encoded+2] = encoding_string[((input[start+1] & 0x0f) <<  2) | ((input[start+2] & 0xc0) >> 6)];
			output[bytes_encoded+3] = encoding_string[(input[start+2] & 0x3f)];

			start += 3;
			bytes_encoded += 4;
		}

		if (bytes_encoded < max_bytes)
		{
			/* ok, we have less than three bytes left to decode */
			if ((input_size - start) == 2)
			{
				output[bytes_encoded]   = encoding_string[(input[start] >> 2)];
				output[bytes_encoded+1] = encoding_string[((input[start] & 0x03) << 4) | ((input[start+1] & 0xf0) >> 4)];
				output[bytes_encoded+2] = encoding_string[((input[start+1] & 0x0f) <<  2)];
				output[bytes_encoded+3] = '=';
				start += 2;
			}
			else if ((input_size - start) == 1)
			{
				output[bytes_encoded]   = encoding_string[(input[start] >> 2)];
				output[bytes_encoded+1] = encoding_string[(input[start] & 0x03) << 4];
				output[bytes_encoded+2] = '=';
				output[bytes_encoded+3] = '=';

				start++;
			}
			bytes_encoded += 4;
		}

		output[bytes_encoded] = 0;
	}
	return bytes_encoded;
}

/*------------------------------------------------------------* 
 * This function will convert the base64 to hex values.
 * 
 * The function will decode the input buffer into the output
 * buffer. It will return the number of bytes that it
 * converted.
 *
 *    +--------+--------+--------+--------+
 *    | byte 1 | byte 2 | byte 3 | byte 4 |
 *    +--------+--------+--------+--------+
 * dec:  aaaaaa   aabbbb   bbbbcc   cccccc
 *
 * 1:    0x3F |  0x30
 * 2:            0x0F      0x3c
 * 3:                      0x03     0x3F
 *------------------------------------------------------------*/
unsigned int	decode_base64(unsigned char* output,unsigned int output_size,unsigned char* input,unsigned int input_size)
{	
	int				in_pos = 0;
	unsigned int	bytes_decoded = 0;

	while (((bytes_decoded + 3) < output_size) && (in_pos < input_size))
	{
		output[bytes_decoded  ] = ((decoded_byte[input[in_pos]] << 2) | ((decoded_byte[input[in_pos+1]] & 0x30) >> 4));
		output[bytes_decoded+1] = (((decoded_byte[input[in_pos+1]] & 0x0F) << 4) | ((decoded_byte[input[in_pos+2]] & 0x3c) >> 2));
		output[bytes_decoded+2] = ((decoded_byte[input[in_pos+2]] & 0x03) << 6) | decoded_byte[input[in_pos+3]];

		bytes_decoded += 3;
		in_pos += 4;
	}

	return bytes_decoded;
}
