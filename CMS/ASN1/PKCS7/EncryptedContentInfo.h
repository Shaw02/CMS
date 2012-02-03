#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			�萔��`											*/
/****************************************************************/
#define	Encrypt_Buff		2048


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

	unsigned	int		szContent;

//--------------
//�֐�
						EncryptedContentInfo(const char _strName[]="EncryptedContentInfo");
						~EncryptedContentInfo(void);

				void	Set(ObjectIdentifier*		_type,
							Encryption*				_algorithm,
							unsigned	int			_szContent);
				int		encrypt(unsigned char* CEK, FileInput* f_Plain, FileOutput* f_Cipher);
				int		decrypt(unsigned char* CEK, FileInput* f_Cipher, FileOutput* f_Plain);
};
