/*------------------------------------------------------------
 * DumpHexMem
 * This function will dump the memory passed in as hex to the
 * file that is passed in. This can be STDIN.
 *------------------------------------------------------------*/ 

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
	#include <io.h>
#else
	#include <unistd.h>
#endif

#include <ctype.h>
#include <memory.h>

static char	HexBit[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

void	DumpHexMem(char* memory,unsigned long dumpSize)
{
	int	count,count2,count3,count4;
	char	line[89];

	/* write the straplines */
	printf("                     Hex Dump                                          Characters      \n");
	printf("                     ------------------------------------------------  ----------------\n");

	/* clear the space under the timestamp */
	memset(line,' ',86);
	
	/* now dump the rest */
	for (count=0;count < dumpSize;count+=16)
	{
		for(count2=count,count3=21,count4=71;count2 < count+16 && count2 < dumpSize;count2++,count3+=3,count4++)
		{
			/* do the main hex conversion */
			line[count3] = HexBit[((memory[count2]&0xf0)>>4)];
			line[count3+1] = HexBit[(memory[count2]&0x0f)];
			line[count3+2] = ' ';

			/* do the end stuff */
			if (!isprint(memory[count2]))
				line[count4] = '.';
			else
				line[count4] = (char) memory[count2];

		}

		if (count2 < count+16)
		{
			for(;count2<count+16;count2++,count3+=3,count4++)
			{
				line[count3] = ' ';
				line[count3+1] = ' ';
				line[count3+2] = ' ';

				line[count4] = ' ';
			}
		}

		line[87] = '\n';
		line[88] = '\0';
		printf("%s",line);
	}
}


