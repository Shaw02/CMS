#pragma once
#include "..\BER_Output.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PKCS8 :
	public PrivateKeyInfo
{
public:
			PKCS8(const char _strName[]="PKCS#7");
			~PKCS8(void);
};
