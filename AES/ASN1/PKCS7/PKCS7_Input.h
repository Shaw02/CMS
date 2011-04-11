#pragma once
#include "../BER_Input.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class PKCS7_Input :
	public BER_Input,
	public ContentInfo
{
public:


public:
	PKCS7_Input(const char*	strFileName);
	~PKCS7_Input(void);

unsigned	int		Get_ContentInfo(unsigned int type);
};
