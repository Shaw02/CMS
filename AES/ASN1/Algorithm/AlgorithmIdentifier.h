#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			ÉNÉâÉXíËã`											*/
/****************************************************************/
class AlgorithmIdentifier :
	public Sequence
{
public:
//--------------
//ïœêî
/*
AlgorithmIdentifier ::= SEQUENCE  {
  algorithm OBJECT IDENTIFIER,
  parameters ANY DEFINED BY algorithm OPTIONAL  }
*/
	ObjectIdentifier	algorithm;

//--------------
//ä÷êî
						AlgorithmIdentifier(const char _strName[]="AlgorithmIdentifier");
						~AlgorithmIdentifier(void);

				void	Set(unsigned int i[],unsigned int n);
};
