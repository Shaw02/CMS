#pragma once
#include "fileinput.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class BER_Input :
	public FileInput
{
public:
					BER_Input(const char*	strFileName);
					~BER_Input(void);

			void	DecodeError(unsigned int iEer);
			int		read_int(int iSize);
unsigned	int		read_uint(int iSize);
unsigned	int		read_variable(void);
			void	read_TAG(unsigned char* cClass, bool* fStruct, unsigned int* iTag);
unsigned	int		read_TAG_with_Check(unsigned char cClass, unsigned int iTag, bool* fStruct);

unsigned	int		read_Integer(Integer* i);
unsigned	int		read_Object_Identifier(ObjectIdentifier* oid);
unsigned	int		read_Object_Identifier_with_Check(
						ObjectIdentifier*	oid,
						unsigned	int		iData[],
						unsigned	int		szData
				);

unsigned	int		read_Octet_Strings(void);
};
