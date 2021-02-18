#pragma once
#include "ASN1.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class ObjectIdentifier :
	public ASN1
{
public:
//--------------
//•Ï”
	vector<int>			iValue;

//--------------
//ŠÖ”
						ObjectIdentifier(const char _strName[]="Object Identifier");
						ObjectIdentifier(unsigned int i[], unsigned int n, const char _strName[]="Object Identifier");
						~ObjectIdentifier(void);

				void	encodeBER();
				void	Set(unsigned int i[],size_t n);
				void	SetVector(vector<unsigned int> i);
};
