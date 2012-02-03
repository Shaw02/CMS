#pragma once
#include "ASN1.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class Set :
	public ASN1
{
public:
//--------------
//•Ï”


//--------------
//ŠÖ”
						Set(const char _strName[]="Set");
						~Set(void);

	virtual		void	encodeBER();
};
