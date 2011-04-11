#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PrivateKeyInfo :
	public Sequence
{
public:
//--------------
//�ϐ�
/*
PrivateKeyInfo ::= SEQUENCE {
  version                   Version,
  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
  privateKey                PrivateKey,
  attributes           [0]  IMPLICIT Attributes OPTIONAL }

*/
	Integer					version;
	AlgorithmIdentifier*	privateKeyAlgorithm;	//�|�C���^�[�ŋL������B
	OctetString				privateKey;
//	Set						attributes;

//--------------
//�֐�
						PrivateKeyInfo(const char _strName[]="PrivateKeyInfo");
						~PrivateKeyInfo(void);

				void	Set(AlgorithmIdentifier*	_algorithm,
										char		c[],
							unsigned	int			iSize);
};
