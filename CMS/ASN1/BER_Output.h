#pragma once
#include "fileoutput.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class BER_Output :
	public FileOutput
{
public:
//--------------
//�ϐ�

//--------------
//�֐�
								BER_Output(const char*	strFileName);
								~BER_Output(void);

						void	write_BERcode(const	char* strCode, size_t szCode);
};
