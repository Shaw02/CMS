#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class AlgorithmIdentifier :
	public Sequence
{
public:
//--------------
//�ϐ�
/*
AlgorithmIdentifier ::= SEQUENCE  {
  algorithm OBJECT IDENTIFIER,
  parameters ANY DEFINED BY algorithm OPTIONAL  }
*/
	ObjectIdentifier	algorithm;

//--------------
//�֐�
						AlgorithmIdentifier(const char _strName[]="AlgorithmIdentifier");
						~AlgorithmIdentifier(void);

				void	Set(unsigned int i[],unsigned int n);
};
