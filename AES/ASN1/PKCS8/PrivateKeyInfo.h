#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PrivateKeyInfo :
	public Sequence
{
public:
//--------------
//変数
/*
PrivateKeyInfo ::= SEQUENCE {
  version                   Version,
  privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
  privateKey                PrivateKey,
  attributes           [0]  IMPLICIT Attributes OPTIONAL }

*/
	Integer					version;
	AlgorithmIdentifier*	privateKeyAlgorithm;	//ポインターで記憶する。
	OctetString				privateKey;
//	Set						attributes;

//--------------
//関数
						PrivateKeyInfo(const char _strName[]="PrivateKeyInfo");
						~PrivateKeyInfo(void);

				void	Set(AlgorithmIdentifier*	_algorithm,
										char		c[],
							unsigned	int			iSize);
};
