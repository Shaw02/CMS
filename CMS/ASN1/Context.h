#pragma once
#include "ASN1.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class Context :
	public ASN1
{
public:
//-------------
//�ϐ�
	unsigned	int		number;
	vector<string>		strValue;	//ASN.1�ȊO�̃f�[�^������ꍇ�B

//--------------
//�֐�
						Context(unsigned int num, const char _strName[]="Context");
						~Context(void);

	virtual		void	encodeBER();
				void	Set(string strData);
};
