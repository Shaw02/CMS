#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/



/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PasswordRecipientInfo :
	public Sequence
{
public:
//--------------
//変数
/*
PasswordRecipientInfo ::= SEQUENCE {
  version CMSVersion,   -- Always set to 0
  keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
  keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
  encryptedKey EncryptedKey }
*/
	Integer					version;					//cmsVersion
	KeyDerivation*			keyDerivation;				//※このクラス側で解放する。
	Context					keyDerivationAlgorithm;
	Encryption*				keyEncryptionAlgorithm;		//※このクラス側で解放する。
	OctetString				EncryptedKey;				//

//--------------
//関数
						PasswordRecipientInfo(const char _strName[]="PasswordRecipientInfo");
						~PasswordRecipientInfo(void);

				void	SetInfo(KeyDerivation* _keyDerivation, Encryption* keyEncryption);

				void	SetKey(void* ptPassword, size_t szPassword, void* Key, size_t szKey);
				size_t	GetKey(void* ptPassword, size_t szPassword, void* Key, size_t szKey);
};
