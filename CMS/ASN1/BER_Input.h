#pragma once
#include "FileInput.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class BER_Input :
	public FileInput
{
public:
//--------------
//•Ï”

//--------------
//ŠÖ”
					BER_Input(const char*	strFileName);
					~BER_Input(void);

			void	DecodeError(unsigned int iEer);
			int		read_int(size_t iSize);
unsigned	int		read_uint(size_t iSize);
unsigned	int		read_variable(void);
			size_t	read_TAG(unsigned char* cClass, bool* fStruct, unsigned int* iTag);
			size_t	read_TAG_with_Check(unsigned char cClass, bool fStruct, unsigned int iTag);

			size_t	read_Integer(Integer* i);
			size_t	read_Object_Identifier(ObjectIdentifier* oid);
			size_t	read_Object_Identifier_with_Check(
						ObjectIdentifier*	oid,
						unsigned	int		iData[],
									size_t	szData);
			size_t	read_Octet_Strings(OctetString* _str);
};
