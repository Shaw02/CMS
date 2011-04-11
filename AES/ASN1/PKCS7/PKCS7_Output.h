#pragma once
#include "..\BER_Output.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class PKCS7_Output :
	public BER_Output, 
	public ContentInfo
{
public:
		PKCS7_Output(const char*	strFileName);
		~PKCS7_Output(void);

		void	Set_for_PKCS7(unsigned int type);
};
