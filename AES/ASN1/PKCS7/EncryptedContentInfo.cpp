#include "StdAfx.h"
#include "EncryptedContentInfo.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
EncryptedContentInfo::EncryptedContentInfo(const char _strName[]):
	Sequence(_strName),
	encryptedContent(0)
{
}

//==============================================================
//		�f�X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
EncryptedContentInfo::~EncryptedContentInfo(void)
{
}

//==============================================================
//				�I�u�W�F�N�g�̐ݒ�
//--------------------------------------------------------------
//	������
//			ObjectIdentifier*		_type		�Í����̃^�C�v
//			AlgorithmIdentifier*	_algorithm	�Í��A���S���Y��
//			unsigned	int			_szContent	�Í����̃T�C�Y�i���̂͂Ƃ肠�����O���Ɂj
//	���Ԓl
//			����
//==============================================================
void	EncryptedContentInfo::Set(
			ObjectIdentifier*		_type,
			AlgorithmIdentifier*	_algorithm,
			unsigned	int			_szContent)
{
	//contentType ContentType
	contentType	= _type;
	Set_Construct(contentType);

	//contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier
	contentEncryptionAlgorithm = _algorithm;
	Set_Construct(contentEncryptionAlgorithm);

	//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
	encryptedContent.Set_ExternalDataSize(_szContent);
	Set_Construct(&encryptedContent);
}
