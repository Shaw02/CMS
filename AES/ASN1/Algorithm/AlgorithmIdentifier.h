#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class AlgorithmIdentifier :
	public Sequence
{
public:
//--------------
//変数
/*
AlgorithmIdentifier ::= SEQUENCE  {
  algorithm OBJECT IDENTIFIER,
  parameters ANY DEFINED BY algorithm OPTIONAL  }
*/
	ObjectIdentifier	algorithm;

//--------------
//関数
						AlgorithmIdentifier(const char _strName[]="AlgorithmIdentifier");
						~AlgorithmIdentifier(void);

				void	Set(unsigned int i[],unsigned int n);
};
