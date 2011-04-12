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
//		�w�b�_�[�\���`�F�b�N
//--------------------------------------------------------------
//	������
//			
//	���Ԓl
//			
//==============================================================
unsigned	int		PKCS7_6_Input::Get_EncryptedData(void)
{
	//ContentInfo
	Get_ContentInfo(EncryptedData_type);

		//EnvelopedData
		read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

			//version
			read_Integer(&encrypted_data.version);
			if(encrypted_data.version.iValue != 0){
				error(0);	//���Ή���Version
			}
			encrypted_data.Set_Construct(&encrypted_data.version);

			//encryptedContentInfo
			read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

				//contentType 
				read_Object_Identifier(&contentType);
				encrypted_data.encryptedContentInfo.Set_Construct(&contentType);

				//EncryptionAlgorithm
				szAlgorithm	= read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
				ptAlgorithm	= tellg();
				read_Object_Identifier(&Algorithm);
				ptAlgorithmPara	= tellg();
				StreamPointerMove(ptAlgorithm + szAlgorithm);

				//�����ɓ����Ă���̂��A�Í������̂̃T�C�Y
				szEncryptedContent = read_TAG_with_Check(BER_Class_Context, false, 0);
				ptEncryptedContent	= tellg();

		//------
		//����
		context.Set_Construct(&encrypted_data);		//ContentInfo�N���X��member

	return(szEncryptedContent);
}
//--------------------------------
//	��΃V�[�N	Algorithm
//--------------------------------
void	PKCS7_6_Input::StreamPointerMove_AlgorithmPara(void)
{
	StreamPointerMove(ptAlgorithmPara);
}
//--------------------------------
//	��΃V�[�N	EncryptedContent
//--------------------------------
void	PKCS7_6_Input::StreamPointerMove_EncryptedContent(void)
{
	StreamPointerMove(ptEncryptedContent);
}
