#pragma once
#include "ASN1.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class Integer :
	public ASN1
{
public:
//--------------
//�ϐ�
				int		iValue;

//--------------
//�֐�
						Integer(const char _strName[]="Integer");
						~Integer(void);

				void	encodeBER();
				void	Set(int i);
};
