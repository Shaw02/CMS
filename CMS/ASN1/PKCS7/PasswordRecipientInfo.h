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
	Encryption*				keyEncryptionAlgorithm;
	OctetString				EncryptedKey;				//

//--------------
//�֐�
						PasswordRecipientInfo(const char _strName[]="PasswordRecipientInfo");
						~PasswordRecipientInfo(void);

				void	SetInfo(KeyDerivation* _keyDerivation, Encryption* keyEncryption);

				void	SetKey(void* ptPassword, unsigned int szPassword, void* Key, unsigned int szKey);
				void	GetKey(void* ptPassword, unsigned int szPassword, void* Key, unsigned int szKey);
};
