#pragma once
#include "ASN1.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class Sequence :
	public ASN1
{
public:
//--------------
//変数


//--------------
//関数
						Sequence(const char _strName[]="Sequence");
						~Sequence(void);

	virtual		void	encodeBER();
};
