#pragma once
#include "ASN1.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class Sequence :
	public ASN1
{
public:
//--------------
//�ϐ�


//--------------
//�֐�
						Sequence(const char _strName[]="Sequence");
						~Sequence(void);

	virtual		void	encodeBER();
};
