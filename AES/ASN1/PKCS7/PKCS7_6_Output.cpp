#include "StdAfx.h"
#include "PKCS7_6_Output.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PKCS7_6_Output::PKCS7_6_Output(const char*	strFileName):
	PKCS7_Output(strFileName)
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
PKCS7_6_Output::~PKCS7_6_Output(void)
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
//	������
//			(1)	object "EncryptedData" ��ݒ肷��B
//			(2)	Context[0]�ɁA�ݒ肵��object "EncryptedData" ���i�[����B
//			(3) object "ContentInfo" �i��this class�j��ݒ肷��B
//==============================================================
void	PKCS7_6_Output::Set_EncryptedData(
			ObjectIdentifier*		_type,
			AlgorithmIdentifier*	_algorithm, 
			unsigned	int			_szContent)
{
	//------
	//����
	encrypted_data.Set(_type, _algorithm, _szContent);
	context.Set_Construct(&encrypted_data);		//ContentInfo�N���X��member
	Set_for_PKCS7(EncryptedData_type);
}

//==============================================================
//				�t�@�C����
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//	������
//			�O���f�[�^�̌��ɂ�BER�G���R�[�h���ꂽ�f�[�^������ƃ_���B
//==============================================================
void	PKCS7_6_Output::write_header(void)
{
	encodeBER();
	write_BERcode(Get_BERcode(), Get_BERsize());
}