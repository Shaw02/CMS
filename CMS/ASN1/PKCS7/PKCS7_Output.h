#pragma once
#include "..\BER_Output.h"
#include "PKCS7.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class PKCS7_Output :
	public BER_Output, 
	public PKCS7
{
public:
		PKCS7_Output(const char* strFileName,const char _strName[]="PKCS#7");
		~PKCS7_Output(void);

		void		write_header(void);
};
