#pragma once
#include "fileoutput.h"

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class BER_Output :
	public FileOutput
{
public:
//--------------
//•Ï”

//--------------
//ŠÖ”
								BER_Output(const char*	strFileName);
								~BER_Output(void);

						void	write_BERcode(const	char* strCode, size_t szCode);
};
