#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			定数定義											*/
/****************************************************************/
#define	Encrypt_Buff		2048


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
	//メンバー
	ObjectIdentifier*		contentType;					//暗号文のType
	Encryption*				contentEncryptionAlgorithm;		//暗号アルゴリズム
	Context					encryptedContent;				//暗号文の実体

	unsigned	int		szContent;

//--------------
//関数
						EncryptedContentInfo(const char _strName[]="EncryptedContentInfo");
						~EncryptedContentInfo(void);

				void	Set(ObjectIdentifier*		_type,
							Encryption*				_algorithm,
							unsigned	int			_szContent);
				int		encrypt(unsigned char* CEK, FileInput* f_Plain, FileOutput* f_Cipher);
				int		decrypt(unsigned char* CEK, FileInput* f_Cipher, FileOutput* f_Plain);
};
