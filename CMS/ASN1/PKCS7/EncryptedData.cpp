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
//			Encryption*				_algorithm	�Í��A���S���Y��
//			unsigned	int			_szContent	�Í����̃T�C�Y�i���̂͂Ƃ肠�����O���Ɂj
//	���Ԓl
//			����
//==============================================================
void	EncryptedData::Set(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm, 
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
/*
//==============================================================
//				�Í�
//--------------------------------------------------------------
//	������
//			unsigned char*	CEK			�Í���
//			FileInput*		f_Plain		���̓t�@�C���i�����j
//			FileOutput*		f_Cipher	�o�̓t�@�C���i�Í����j
//			unsigned int	szContent	�T�C�Y
//	���Ԓl
//			int				0			����i���ꂵ���Ԃ��Ȃ����ǁc�j
//							-1			�ُ�
//	������
//			������O��ASN.1�f�[�^�́A���O�ɃG���R�[�h���ăt�@�C���ɏo�͂��Ă������B
//			����"f_Cipher"�ɂ́A��q�̓r���܂ŃG���R�[�h���ꂽ�t�@�C���I�u�W�F�N�g��n���B
//==============================================================
int		EncryptedData::encrypt(
			unsigned char*	CEK,
			FileInput*	f_Plain, 
			FileOutput*	f_Cipher,
			unsigned int szContent)
{
	unsigned	int	iResult;

	iResult = encryptedContentInfo.encrypt(CEK, f_Plain, f_Cipher, szContent);

	return(iResult);
}
*/
