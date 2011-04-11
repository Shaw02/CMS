#include "StdAfx.h"
#include "EncryptedData.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
EncryptedData::EncryptedData(const char _strName[]):
	Sequence(_strName)
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
EncryptedData::~EncryptedData(void)
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
void	EncryptedData::Set(
			ObjectIdentifier*		_type,
			AlgorithmIdentifier*	_algorithm, 
			unsigned	int			_szContent)
{
	unsigned	int	iVersion;

	//------
	//version CMSVersion
	if(unprotectedAttrs.Constructed.size()>0){
		iVersion = 2;
	} else {
		iVersion = 0;
	}
	version.Set(iVersion);
	Set_Construct(&version);

	//------
	//encryptedContentInfo EncryptedContentInfo
	encryptedContentInfo.Set(_type, _algorithm, _szContent);
	Set_Construct(&encryptedContentInfo);

	//------
	//unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
	if(iVersion == 2){

		//	to do	������������ꍇ�̏����B

		Set_Construct(&unprotectedAttrs);
	}
}