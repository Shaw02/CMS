#pragma once
#include "..\Sequence.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/



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
	ObjectIdentifier*		contentType;					//�Í�����Type
	AlgorithmIdentifier*	contentEncryptionAlgorithm;		//�Í��A���S���Y��
	Context					encryptedContent;				//�Í����̎���
//--------------
//�֐�
						EncryptedContentInfo(const char _strName[]="EncryptedContentInfo");
						~EncryptedContentInfo(void);

				void	Set(ObjectIdentifier*		_type,
							AlgorithmIdentifier*	_algorithm,
							unsigned	int			_szContent);
};
