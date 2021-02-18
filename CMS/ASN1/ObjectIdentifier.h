#pragma once
#include "ASN1.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class ObjectIdentifier :
	public ASN1
{
public:
//--------------
//�ϐ�
	vector<int>			iValue;

//--------------
//�֐�
						ObjectIdentifier(const char _strName[]="Object Identifier");
						ObjectIdentifier(unsigned int i[], unsigned int n, const char _strName[]="Object Identifier");
						~ObjectIdentifier(void);

				void	encodeBER();
				void	Set(unsigned int i[],size_t n);
				void	SetVector(vector<unsigned int> i);
};
