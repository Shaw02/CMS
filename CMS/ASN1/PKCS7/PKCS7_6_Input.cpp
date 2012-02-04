#include "StdAfx.h"
#include "PKCS7_6_Input.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PKCS7_6_Input::PKCS7_6_Input(const char*	strFileName):
	PKCS7_Input(strFileName)
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
PKCS7_6_Input::~PKCS7_6_Input(void)
{
}
//==============================================================
//		�y�t�@�C���ǂݍ��݁zEnvelopedData
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
void	PKCS7_6_Input::Get_EncryptedData()
{
	//ContentInfo
	read_ContentInfo(EncryptedData_type);

	//EnvelopedData
	ptEncryptedContent = read_EncryptedData(&encrypted_data);
}
//==============================================================
//				�Í����W���[���ƁA�Í����̏���
//--------------------------------------------------------------
//	������
//			PKCS8_Input*		f_Key			�Í����iKey�t�@�C���j
//	���Ԓl
//			����
//	������
//			�Í����i*.Key�j�t�@�C�����A�Í����ɂ���B
//==============================================================
void	PKCS7_6_Input::Set_Encryption(
			PKCS8_Input*		f_KEY)
{
	Encryption*			cCE		= encrypted_data.encryptedContentInfo.contentEncryptionAlgorithm;
	unsigned	char*	_CEK	= new unsigned char [cCE->szKey];

	//------------------
	//���擾
	f_KEY->Get_PrivateKey_with_check(cCE, _CEK, cCE->szKey);
	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;

}
//==============================================================
//				�Í���
//--------------------------------------------------------------
//	������
//			string*				strPassword		�p�X���[�h
//	���Ԓl
//			����
//	������
//			�p�X���[�h���Í����ɂ���B
//==============================================================
void	PKCS7_6_Input::Set_Encryption(
			string*				strPassword)
{
	Encryption*			cCE		= encrypted_data.encryptedContentInfo.contentEncryptionAlgorithm;
	unsigned	char*	_CEK	= new unsigned char [cCE->szKey];

	//------------------
	//Password������̃n�b�V���l���A�Í����ɂ���B
	cSHA256.CalcHash(_CEK, (void *)strPassword->c_str(), strPassword->length());
	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;

}
//==============================================================
//				�Í���
//--------------------------------------------------------------
//	������
//			FileOutput*			f_Plain			�����t�@�C��
//	���Ԓl
//			����
//	������
//			�Í����i*.Key�j�t�@�C�����Í����ɂ��ĈÍ���
//==============================================================
void	PKCS7_6_Input::decrypt(
			FileOutput*			f_Plain)
{
	int	iResult;

	//�Í����{��
	StreamPointerMove(ptEncryptedContent);
	iResult = encrypted_data.encryptedContentInfo.decrypt((unsigned char*)CEK.strValue.c_str(), this, f_Plain);

	if(iResult != 0){
		errPrint("Decrypt",": Content-Encryption-Key may be different.");
	}
}
