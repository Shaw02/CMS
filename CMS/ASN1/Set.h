#pragma once
#include "ASN1.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class Set :
	public ASN1
{
public:
//--------------
//変数


//--------------
//関数
						Set(const char _strName[]="Set");
						~Set(void);

	virtual		void	encodeBER();
};
