#pragma once
#include "ASN1.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class OctetString :
	public ASN1
{
public:
//--------------
//変数
	string				strValue;

//--------------
//関数
						OctetString(const char _strName[]="Octet String");
						~OctetString(void);

				void	encodeBER();
				void	Set(char i[],unsigned int iSise);
};
