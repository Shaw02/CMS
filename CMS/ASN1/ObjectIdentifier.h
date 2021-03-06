#pragma once
#include "ASN1.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class ObjectIdentifier :
	public ASN1
{
public:
//--------------
//変数
	vector<int>			iValue;

//--------------
//関数
						ObjectIdentifier(const char _strName[]="Object Identifier");
						ObjectIdentifier(unsigned int i[], unsigned int n, const char _strName[]="Object Identifier");
						~ObjectIdentifier(void);

				void	encodeBER();
				void	Set(unsigned int i[],unsigned int n);
				void	SetVector(vector<unsigned int> i);
};
