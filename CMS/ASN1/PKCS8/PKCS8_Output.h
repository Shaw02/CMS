#pragma once
#include "..\BER_Output.h"
#include "PKCS8.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PKCS8_Output :
	public BER_Output, 
	public PKCS8
{
public:
			PKCS8_Output(const char*	strFileName,const char _strName[]="PKCS#8");
			~PKCS8_Output(void);
	void	encodeBER_to_File(void);
};
