#pragma once
#include "fileoutput.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class BER_Output :
	public FileOutput
{
public:
//--------------
//変数

//--------------
//関数
								BER_Output(const char*	strFileName);
								~BER_Output(void);

						void	write_BERcode(const	char* strCode, unsigned int szCode);
};
