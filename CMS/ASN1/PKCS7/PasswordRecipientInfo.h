#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/



/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PasswordRecipientInfo :
	public Sequence
{
public:
//--------------
//�ϐ�
/*
PasswordRecipientInfo ::= SEQUENCE {
  version CMSVersion,   -- Always set to 0
  keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
  keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
  encryptedKey EncryptedKey }
*/
	Integer					version;					//cmsVersion
	KeyDerivation*			keyDerivation;				//�����̃N���X���ŉ������B
	Context					keyDerivationAlgorithm;
	Encryption*				keyEncryptionAlgorithm;		//�����̃N���X���ŉ������B
	OctetString				EncryptedKey;				//

//--------------
//�֐�
						PasswordRecipientInfo(const char _strName[]="PasswordRecipientInfo");
						~PasswordRecipientInfo(void);

				void	SetInfo(KeyDerivation* _keyDerivation, Encryption* keyEncryption);

				void	SetKey(void* ptPassword, size_t szPassword, void* Key, size_t szKey);
				size_t	GetKey(void* ptPassword, size_t szPassword, void* Key, size_t szKey);
};
