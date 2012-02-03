#include "StdAfx.h"
#include "PKCS8_Input.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PKCS8_Input::PKCS8_Input(const char*	strFileName,const char _strName[]):
	BER_Input(strFileName),
	PKCS8(_strName)
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
PKCS8_Input::~PKCS8_Input(void)
{
}
//==============================================================
//		�w�b�_�[�\���`�F�b�N
//--------------------------------------------------------------
//	������
//			unsigned	char	cType	�R���e���c�^�C�v
//	���Ԓl
//			unsigned	int				�R���e���c�̃T�C�Y
//==============================================================
void	PKCS8_Input::Get_PrivateKeyInfo()
{
	unsigned	int		szAlgorithm;
	unsigned	int		ptAlgorithm;

	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

 		//version                   Version,
		read_Integer(&version);
		if(version.iValue != 0){
			error(0);	//���Ή���Version
		}

		//privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
		szAlgorithm	= read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
		ptAlgorithm	= tellg();
		read_Object_Identifier(&Algorithm);		//OID�����ǂ�
		StreamPointerMove(ptAlgorithm + szAlgorithm);

		//privateKey                PrivateKey,
		read_Octet_Strings(&privateKey);

		//attributes           [0]  IMPLICIT Attributes OPTIONAL }
}
//==============================================================
//		�w�b�_�[�\���`�F�b�N
//--------------------------------------------------------------
//	������
//			unsigned	char*		_key		�Í������i�[����|�C���^
//			unsigned	int			_szKey		�Í����̃T�C�Y�i�`�F�b�N�p�j
//	���Ԓl
//			unsigned	char*					�Í���
//==============================================================
void	PKCS8_Input::Get_PrivateKey(
			unsigned	char*		_key,
			unsigned	int			_szKey)
{
	if(privateKey.strValue.size() != _szKey){
		errPrint("Key",": unmatch key size.");
	}
	memcpy(_key, privateKey.strValue.c_str(), _szKey);
}
//==============================================================
//		�w�b�_�[�\���`�F�b�N
//--------------------------------------------------------------
//	������
//			algorithmIdentifier*	_algorithm	�Í��A���S���Y��
//			unsigned	char*		_key		�Í������i�[����|�C���^
//			unsigned	int			_szKey		�Í����̃T�C�Y�i�`�F�b�N�p�j
//	���Ԓl
//			unsigned	char*					�Í���
//==============================================================
void	PKCS8_Input::Get_PrivateKey_with_check(
			AlgorithmIdentifier*	_algorithm,
			unsigned	char*		_key,
			unsigned	int			_szKey)
{
	unsigned	int		i = 0;

	//ASN.1 �\������
	Get_PrivateKeyInfo();

	//�Í��A���S���Y���@�`�F�b�N
	do{
		if(_algorithm->algorithm.iValue[i] != Algorithm.iValue[i]){
			errPrint("PrivateKey",": Different encryption algorithm.");
		}
		i++;
	} while(i < _algorithm->algorithm.iValue.size());

	Get_PrivateKey(_key, _szKey);
}