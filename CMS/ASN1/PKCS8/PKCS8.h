#pragma once
#include "..\BER_Output.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PKCS8 :
	public PrivateKeyInfo
{
public:
			PKCS8(const char _strName[]="PKCS#7");
			~PKCS8(void);
};
