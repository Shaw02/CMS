#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			ÉNÉâÉXíËã`											*/
/****************************************************************/
class ContentInfo :
	public Sequence
{
public:
//--------------
//ïœêî
/*
ContentInfo ::= SEQUENCE {
  contentType ContentType,
  content [0] EXPLICIT ANY DEFINED BY contentType }

*/
	ObjectIdentifier	contentType;
	Context				context;

//--------------
//ä÷êî
						ContentInfo(const char _strName[]="ContentInfo");
						~ContentInfo(void);

				void	Set(unsigned int i[],unsigned int n);
};
