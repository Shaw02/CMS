#pragma once
#include "ASN1.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class Set :
	public ASN1
{
public:
//--------------
//�ϐ�


//--------------
//�֐�
						Set(const char _strName[]="Set");
						~Set(void);

	virtual		void	encodeBER();
};
