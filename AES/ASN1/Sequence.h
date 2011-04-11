#pragma once
#include "ASN1.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class Sequence :
	public ASN1
{
public:
//--------------
//•Ï”


//--------------
//ŠÖ”
						Sequence(const char _strName[]="Sequence");
						~Sequence(void);

	virtual		void	encodeBER();
};
