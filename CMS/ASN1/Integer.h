#pragma once
#include "ASN1.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class Integer :
	public ASN1
{
public:
//--------------
//•Ï”
				int		iValue;

//--------------
//ŠÖ”
						Integer(const char _strName[]="Integer");
						~Integer(void);

				void	encodeBER();
				void	Set(int i);
};
