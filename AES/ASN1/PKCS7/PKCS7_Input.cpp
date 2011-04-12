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

	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

		//OID
		read_Object_Identifier_with_Check(&contentType, oid_pkcs7, sizeof(oid_pkcs7)/sizeof(int));

		//Content Info
		szAddValue = read_TAG_with_Check(BER_Class_Context, true, 0);

	return(szAddValue);
}
