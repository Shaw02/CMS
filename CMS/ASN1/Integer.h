#pragma once
#include "ASN1.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class Integer :
	public ASN1
{
public:
//--------------
//変数
				__int64	iValue;

//--------------
//関数
						Integer(const char _strName[]="Integer");
						~Integer(void);

				void	encodeBER();
				void	Set(__int64 i);
};
