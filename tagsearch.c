/*********************************************************************************
 * Name: Tag Search
 * Description:
 *
 * This file holds the tag search functions.
 *
 * Date  : 8th March 2009
 * Author: Peter Antoine. 
 *
 *********************************************************************************/

unsigned int	TagSearch(unsigned char input,unsigned int input_length,unsigned char **tag_array,unsigned int array_length)
{
	int				count;
	unsigned int	position = 0;

	for(position = 0;found != 0 && position < input_length;position++)
	{
		
		for (count=0;count<array_length;count++)
		{
			if ((position & (0x01 << count)) != 0)
			{
				position |= ((tag_array[count][position] == input[position]) * 0x01) << count;
			}
		}

		:e 

	}
}
