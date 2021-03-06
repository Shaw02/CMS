#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class ContentInfo :
	public Sequence
{
public:
//--------------
//変数
/*
ContentInfo ::= SEQUENCE {
  contentType ContentType,
  content [0] EXPLICIT ANY DEFINED BY contentType }

*/
	ObjectIdentifier	contentType;
	Context				context;

//--------------
//関数
						ContentInfo(const char _strName[]="ContentInfo");
						~ContentInfo(void);

				void	Set(unsigned int i[],unsigned int n);
};
