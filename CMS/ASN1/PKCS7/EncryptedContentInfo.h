#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			�萔��`											*/
/****************************************************************/
#define	Encrypt_Buff		65536


/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class EncryptedContentInfo :
	public Sequence
{
public:
//--------------
//�ϐ�
/*
EncryptedContentInfo ::= SEQUENCE {
  contentType ContentType,
  contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
  encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
*/
	//�����o�[
	ObjectIdentifier*		contentType;					//�Í�����Type
	Encryption*				contentEncryptionAlgorithm;		//�Í��A���S���Y��
	Context					encryptedContent;				//�Í����̎���

	size_t					szContent;

//--------------
//�֐�
						EncryptedContentInfo(const char _strName[]="EncryptedContentInfo");
						~EncryptedContentInfo(void);

				void	Set(ObjectIdentifier*		_type,
							Encryption*				_algorithm,
							size_t					_szContent);
				int		encrypt(unsigned char* CEK, FileInput* f_Plain, FileOutput* f_Cipher);
				int		decrypt(unsigned char* CEK, FileInput* f_Cipher, FileOutput* f_Plain);
};
