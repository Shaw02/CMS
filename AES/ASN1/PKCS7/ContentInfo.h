#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class ContentInfo :
	public Sequence
{
public:
//--------------
//�ϐ�
/*
ContentInfo ::= SEQUENCE {
  contentType ContentType,
  content [0] EXPLICIT ANY DEFINED BY contentType }

*/
	ObjectIdentifier	contentType;
	Context				context;

//--------------
//�֐�
						ContentInfo(const char _strName[]="ContentInfo");
						~ContentInfo(void);

				void	Set(unsigned int i[],unsigned int n);
};
