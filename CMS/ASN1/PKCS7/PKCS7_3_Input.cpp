#include "StdAfx.h"
#include "PKCS7_3_Input.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PKCS7_3_Input::PKCS7_3_Input(const char*	strFileName):
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
PKCS7_3_Input::~PKCS7_3_Input(void)
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
void	PKCS7_3_Input::Get_EnvelopedData()
{
	//ContentInfo
	read_ContentInfo(EnvelopedData_type);

	//EnvelopedData
	ptEncryptedContent = read_EnvelopedData(&enveloped_data);
}
//==============================================================
//				�Í���
//--------------------------------------------------------------
//	������
//			FileOutput*			f_Plain			�����t�@�C��
//	���Ԓl
//			ObjectIdentifier*	_contentType	
//	������
//			�Í����i*.Key�j�t�@�C�����Í����ɂ��ĈÍ���
//==============================================================
void	PKCS7_3_Input::decrypt(
			FileOutput*			f_Plain)
{
	int	iResult;

	//�Í����{��
	StreamPointerMove(ptEncryptedContent);
	iResult = enveloped_data.encryptedContentInfo.decrypt((unsigned char*)CEK.strValue.c_str(), this, f_Plain);

	if(iResult != 0){
		errPrint("Decrypt",": Content-Encryption-Key may be different.");
	}
}
