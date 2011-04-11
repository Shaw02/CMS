#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/



/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class EncryptedContentInfo :
	public Sequence
{
public:
//--------------
//変数
/*
EncryptedContentInfo ::= SEQUENCE {
  contentType ContentType,
  contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
  encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
*/
	ObjectIdentifier*		contentType;					//暗号文のType
	AlgorithmIdentifier*	contentEncryptionAlgorithm;		//暗号アルゴリズム
	Context					encryptedContent;				//暗号文の実体
//--------------
//関数
						EncryptedContentInfo(const char _strName[]="EncryptedContentInfo");
						~EncryptedContentInfo(void);

				void	Set(ObjectIdentifier*		_type,
							AlgorithmIdentifier*	_algorithm,
							unsigned	int			_szContent);
};
