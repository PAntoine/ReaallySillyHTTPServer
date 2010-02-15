/***************************************************************************************
 *
 *       Filename:  ASN.1 Decoder
 *
 *    Description:  This file holds the functions required to decode an ASN.1 formatted
 *                  data file.
 *
 *                  This is not as stream decoder, it expects the whole of the ASN.1
 *                  data file to be loaded into the source data buffer. This avoids any
 *                  code to handle streaming data.
 *
 *                  Also, this is not clever. It does not check sequence length and 
 *                  handle that nonsense, that should be handled in the rest of the
 *                  code.
 *
 *                  I know, but I cant be arsed to do it properly. Demo code people!
 *
 *        Version:  1.0
 *        Created:  20/03/2009 10:12:03
 *       Revision:  nonfe
 *
 *         Author:  Peter Antoine
 *          Email:  me@peterantoine.me.uk
 *
 *------------------------------------------------------------------------------------- 
 *                         Copyright (c) 2009 : Peter Antoine
 *                        Released under the Artistic License.
 ***************************************************************************************/

#include "ASN1_decoder.h"
#include <time.h>
#include <stdio.h>
#include <string.h>

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  ASN1_DecodeHeader
 *  Description:  This function will decode the ASN1 header that is pointed to by
 *                the source_data pointer.
 *
 *                If the function works, it returns the number of bytes that the header
 *                used.
 *                Else, it returns 0.
 *-------------------------------------------------------------------------------------*/
static unsigned int	ASN1_DecodeHeader ( unsigned char* source_data, ASN1_OBJECT* object)
{
	unsigned int	end;
	unsigned int	worked = 1;
	unsigned int	offset = 0;
	unsigned int	tag_size;

	/* initialise the object */
	object->length	= 0;
	object->data	= 0L;
	object->offset	= 0;

	/* check that we have not finished decoding the structure */
	object->asn1_class	= ((source_data[0] & 0xc0) >> 6);
	object->type		= ((source_data[0] & 0x20) >> 5);

	if ((object->tag = (source_data[0] & 0x1F)) != 0x1f)
	{
		offset++;
	}
	else
	{
		/* ok, we have a multi-parter lets get the full length 
		 * I am using a sensible offset, if the tag ID is greater than
		 * a unsigned long, then its too big to handle.
		 */
		object->tag = 0;

		do
		{
			offset++;
			object->tag = ((object->tag << 7) | (source_data[offset] & 0x7f));
		}
		while ((source_data[offset] & 0x80) != 0 && (object->tag & 0x0E000000) == 0);

		if ((source_data[offset] & 0x80) != 0)
		{
			/* tag is too long */
			worked = 0;
		}
		offset++;
	}

	/* decode the length octets */
	if (worked)
	{
		if (source_data[offset] == 0)
		{
			/* W**kers have encoded this with an indefinite length.
			 * We will have to read the rest of the source_data looking 
			 * for the End-Of-Contents octet.
			 *
			 * Can't do this here. It will have to be done during
			 * subsequent decoding.
			 */
			offset++;
			object->length = 0;
		}
		else if ((source_data[offset] & 0x80) == 0)
		{
			/* we have the short form */
			object->length = source_data[offset];
			offset++;
		}
		else if ((source_data[offset] & 0x80) != 0)
		{
			/* we need to read a multibyte length */
			end = offset + (source_data[offset] & 0x7f) +1;
			offset++;
			object->length = 0;

			for (;offset < end;offset++)
			{
				object->length = (object->length << 8) | source_data[offset];
			}
		}

		/* this maybe nonsense if the decoding failed */
		object->data = &source_data[offset];
	}

	if (worked == 0)
		return 0;
	else
		return offset;
}


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  ASN1_GetObject
 *  Description:  This function will populate a ANS1_OBJECT from the data found in the
 *                source buffer.
 *-------------------------------------------------------------------------------------*/
unsigned int ASN1_GetObject ( unsigned char* source_data,ASN1_OBJECT* object )
{
	return ASN1_DecodeHeader(source_data,object);
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  ASN1_GetNextObject
 *  Description:  This function will get the next sub-object from within a ASN1 object.
 *                It uses the source object offset field to find the next item.
 *-------------------------------------------------------------------------------------*/
unsigned int ASN1_GetNextObject ( ASN1_OBJECT* source_object, ASN1_OBJECT* sub_object )
{
	unsigned int	header_size = 0;
	unsigned char*	data;

	if (source_object->length > source_object->offset)
	{
		/* ok, we have not decoded the whole of the object already */
		data = &source_object->data[source_object->offset];

		if ((header_size = ASN1_DecodeHeader(data,sub_object)))
		{
			/* ok, it's a valid decode, lets move the offset on */
			source_object->offset += sub_object->length + header_size;
		}
	}

	return header_size;
}


/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  ASN1_DecodeInteger
 *  Description:  This function will decode the wonderful ASN1 integer to a signed 
 *                integer value. It will handle the ASN1 2's complement on variable
 *                sized numbers.
 *
 *                Note: I will only create up to the max size of a long, if you need
 *                bigger, then fix it yourself.
 *-------------------------------------------------------------------------------------*/
long	ASN1_DecodeInteger ( ASN1_OBJECT* object )
{
	long			result = 0;
	unsigned int	count;

	/* need to sign extend the number */
	if ((object->data[0] & 0x80) != 0)
	{
		result = -1;
	}

	for (count=0;count<object->length;count++)
	{
		result = (result << 8) | object->data[count];
	}

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  ASN1_DecodeBitString
 *  Description:  This function will extract the bit string from the ASN1 bitstring
 *                object.
 *-------------------------------------------------------------------------------------*/
unsigned int ASN1_DecodeBitString ( ASN1_OBJECT* object, unsigned char* buffer, unsigned int buffer_size )
{
	unsigned int result = 0;

	if (buffer_size >= object->length)
	{
		result = ((object->length - 1) * 8) - object->data[0];

		memcpy(buffer,&object->data[1],object->length-1);
	}

	return result;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  ANS1_DecodeUTCTIme
 *  Description:  This function will decode a UTC time object into a "struct tm" object.
 *-------------------------------------------------------------------------------------*/

unsigned int ANS1_DecodeUTCTime ( ASN1_OBJECT* object, struct tm* utc_time )
{
	unsigned int result = 0;

	/* check we have the correct format before we start */
	if (object->length == 13 && object->data[12] == 'Z')
	{
		memset(utc_time,0,sizeof(struct tm));

		utc_time->tm_year = 100 + ( (object->data[0] - '0') * 10 + (object->data[1] - '0'));
		utc_time->tm_mon  = ( (object->data[2] - '0') * 10 + (object->data[3] - '0'));
		utc_time->tm_mday = ( (object->data[4] - '0') * 10 + (object->data[5] - '0'));
		utc_time->tm_hour = ( (object->data[6] - '0') * 10 + (object->data[7] - '0'));
		utc_time->tm_min  = ( (object->data[8] - '0') * 10 + (object->data[9] - '0'));
		utc_time->tm_sec  = ( (object->data[10] - '0') * 10 + (object->data[11] - '0'));

		/* validate the dates */
		if ((utc_time->tm_mon >= 1 && utc_time->tm_mon <= 12)	&&
			(utc_time->tm_mday >= 1 && utc_time->tm_mday <= 31)	&&
			(utc_time->tm_hour >= 0 && utc_time->tm_hour <= 23)	&&
			(utc_time->tm_min >= 0 && utc_time->tm_min <= 59)	&&
			(utc_time->tm_sec >= 0 && utc_time->tm_sec <= 62))
		{
			result = 1;
		}
	}

	return 1;
}

/*---  FUNCTION  ----------------------------------------------------------------------*
 *         Name:  ASN1_DecodeLargeInteger
 *  Description:  This function will essentially copy the contents of the ASN.1 int
 *                to a byte array. It will have the "sign" byte at the front.
 *
 *                Note: We export either a byte that has the high bit set in the first
 *                      byte, or the first byte being 0x00. I am not doing a shifting 
 *                      byte copy. Can't be bothered to write that.
 *-------------------------------------------------------------------------------------*/
unsigned int	ASN1_DecodeLargeInteger( ASN1_OBJECT* object,unsigned char* buffer, unsigned int buffer_size )
{
	unsigned int	result = 0;

	if (buffer_size >= object->length)
	{
		if (object->data[0] == 0x00)
		{
			memcpy(buffer,&object->data[1],object->length-1);
			result = (object->length-1) * 8;
		}
		else if ((object->data[0] & 0x80) == 0x00)
		{
			memcpy(buffer,object->data,object->length);
			result = object->length * 8;
		}
		else
		{
			printf("not copying negative number: %02x\n",object->data[0]);
			/* Not going to handle negative big bit values, no, no, no !! */
			result = 0;
		}
	}

	return result;
}
