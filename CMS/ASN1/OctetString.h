#pragma once
#include "ASN1.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class OctetString :
	public ASN1
{
public:
//--------------
//�ϐ�
	string				strValue;

//--------------
//�֐�
						OctetString(const char _strName[]="Octet String");
						~OctetString(void);

				void	encodeBER();
				void	Set(char i[], size_t iSize);
};
