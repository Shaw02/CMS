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
				__int64	iValue;

//--------------
//�֐�
						Integer(const char _strName[]="Integer");
						~Integer(void);

				void	encodeBER();
				void	Set(__int64 i);
};
