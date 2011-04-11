#include "StdAfx.h"
#include "PKCS7_Input.h"

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PKCS7_Input::PKCS7_Input(const char*	strFileName):
	BER_Input(strFileName),
	ContentInfo("PKCS#7 File input")
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
PKCS7_Input::~PKCS7_Input(void)
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
unsigned int	PKCS7_Input::Get_ContentInfo(unsigned int type)
{
	static	unsigned	int		oid_pkcs7[]	=	{1,2,840,113549,1,7,type};
			unsigned	int		i = 0;
						bool	fStruct;

	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, BER_TAG_SEQUENCE, &fStruct);
	if(fStruct != true){
		DecodeError(0);
	}

		//OID
		read_Object_Identifier_with_Check(&contentType, oid_pkcs7, sizeof(oid_pkcs7)/sizeof(int));

		//Content Info
		szAddValue = read_TAG_with_Check(BER_Class_Context, 0, &fStruct);
		if(fStruct != true){
			DecodeError(0);
		}

	return(szAddValue);
}
