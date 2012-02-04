#pragma once
#include "ASN1.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class Context :
	public ASN1
{
public:
//-------------
//変数
	unsigned	int		number;
	vector<string>		strValue;	//ASN.1以外のデータを入れる場合。

//--------------
//関数
						Context(unsigned int num, const char _strName[]="Context");
						~Context(void);

	virtual		void	encodeBER();
				void	Set(string strData);
};
