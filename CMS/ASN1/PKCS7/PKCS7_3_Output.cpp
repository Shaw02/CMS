#include "StdAfx.h"
#include "PKCS7_3_Output.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PKCS7_3_Output::PKCS7_3_Output(const char*	strFileName):
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
PKCS7_3_Output::~PKCS7_3_Output(void)
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
//	������
//			(1)	object "EncryptedData" ��ݒ肷��B
//			(2)	Context[0]�ɁA�ݒ肵��object "EncryptedData" ���i�[����B
//			(3) object "ContentInfo" �i��this class�j��ݒ肷��B
//==============================================================
void	PKCS7_3_Output::Set_EnvelopedData(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm, 
			unsigned	int			_szContent)
{
	//------
	//����
	enveloped_data.Set(_type, _algorithm, _szContent);
	context.Set_Construct(&enveloped_data);		//ContentInfo�N���X��member
	Set_Type(EnvelopedData_type);
}
//==============================================================
//				�Í����W���[���ƁA�Í����̏���
//--------------------------------------------------------------
//	������
//		unsigned	int		mode		�g�p����R���e���c�Í�
//	���Ԓl
//		����
//	������
//		�Í����W���[����p�ӂ���B
//		�������x�N�^IV, �R���e���c�p�Í���CEK�i�Z�b�V�������j���A�����ō쐬����B
//==============================================================
void	PKCS7_3_Output::MakeEncryption(unsigned int		mode)
{
	unsigned	char*	_CEK;

	//------------------
	//�Í����W���[���̎擾
	cCE = Get_Encryption(mode);

	//------------------
	//�Z�b�V�������͗�����莩������
	_CEK	= new unsigned char [(cCE->szKey<32)?32:cCE->szKey];
	cRandom->get256(_CEK);
	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;
}

//==============================================================
//				��M�ҏ��̒ǉ��i��M�҂́A�p�X���[�h�j
//--------------------------------------------------------------
//	������
//		string*				strPassword		�p�X���[�h
//		unsigned	int		count			PBKDF2�֐��ɐݒ肷��J��Ԃ���
//		unsigned	int		mode			�g�p���錮�Í�
//	���Ԓl
//		�����B
//	������
//		�p�X���[�h���献�Í�����KEK�𓱏o���A�Z�b�V�����������b�v����B
//==============================================================
void	PKCS7_3_Output::AddRecipient(
			string*					strPassword,
			unsigned int			count,
			unsigned int			mode)
{
	//------------------
	//�����o
	enveloped_data.recipientInfos.AddRecipient(strPassword, &CEK, &cHMAC_SHA256, count, mode);
}
//==============================================================
//				�Í���
//--------------------------------------------------------------
//	������
//		FileInput*			f_Plain		����
//		ObjectIdentifier*	contentType	�����̃^�C�v
//	���Ԓl
//		����
//	������
//		MakeEncryption()�Őݒ肵���Í����W���[���i�ƃZ�b�V�������j�ŁA
//		�R���e���c"f_Plain"���Í������A�t�@�C���o�͂���B
//		�����o�[�ϐ�"recipientInfos"�ɂ́A��M�ҏ�񂪓����Ă��鎖�B
//==============================================================
void	PKCS7_3_Output::encrypt(
			FileInput*			f_Plain,
			ObjectIdentifier*	contentType)
{

	//------------------
	//PKCS#7-3 �̃I�u�W�F�N�g�쐬
	Set_EnvelopedData(contentType, cCE, f_Plain->GetSize());

	//------------------
	//�Í��t�@�C���̏o��

	//�Í����{�̂܂�
	write_header();

	//�Í����{��
	enveloped_data.encryptedContentInfo.encrypt((unsigned char*)CEK.strValue.c_str(), f_Plain, this);
}
