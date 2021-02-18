#pragma once
#include "ASN1.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class OctetString :
	public ASN1
{
public:
//--------------
//•Ï”
	string				strValue;

//--------------
//ŠÖ”
						OctetString(const char _strName[]="Octet String");
						~OctetString(void);

				void	encodeBER();
				void	Set(char i[], size_t iSize);
};
