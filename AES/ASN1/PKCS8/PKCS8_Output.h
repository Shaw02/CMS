#pragma once
#include "..\BER_Output.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PKCS8_Output :
	public BER_Output, 
	public PrivateKeyInfo
{
public:
			PKCS8_Output(const char*	strFileName);
			~PKCS8_Output(void);
	void	encodeBER_to_File(void);
};
