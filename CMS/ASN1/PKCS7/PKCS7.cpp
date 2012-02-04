#include "StdAfx.h"
#include "PKCS7.h"


	//�Í�
	__declspec(align(16))	DES_CBC			PKCS7::cDES_CBC;
	__declspec(align(16))	DES_EDE3_CBC	PKCS7::cTDES_CBC;
	__declspec(align(16))	AES_CBC128		PKCS7::cAES_CBC128;		//SIMD���g���֌W�ŁA
	__declspec(align(16))	AES_CBC192		PKCS7::cAES_CBC192;		//static�ɒu���K�v����B
	__declspec(align(16))	AES_CBC256		PKCS7::cAES_CBC256;		//(__declspec(align(16)))

	//�n�b�V��
	SHA1			PKCS7::cSHA1;			//SHA�n�b�V��
	SHA224			PKCS7::cSHA224;			//SHA�n�b�V��
	SHA256			PKCS7::cSHA256;			//SHA�n�b�V��

//==============================================================
//		�R���X�g���N�^
//--------------------------------------------------------------
//	������
//				����
//	���Ԓl
//				����
//==============================================================
PKCS7::PKCS7(const char _strName[]):
	ContentInfo(_strName),
	cHMAC_SHA1(&cSHA1),
	cHMAC_SHA224(&cSHA224),
	cHMAC_SHA256(&cSHA256)
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
PKCS7::~PKCS7(void)
{
}
//==============================================================
//		
//--------------------------------------------------------------
//	������
//				type	�f�[�^�^�C�v
//	���Ԓl
//				����
//==============================================================
void	PKCS7::Set_Type(unsigned int type)
{
	static	unsigned	int		oid_pkcs7[]	=	{1,2,840,113549,1,7,type};

	Set(oid_pkcs7, sizeof(oid_pkcs7)/sizeof(int));
}
//==============================================================
//				�Í����W���[���̎擾
//--------------------------------------------------------------
//	������
//			unsigned int mode	���p����Í�
//	���Ԓl
//			Encryption*			�Í����W���[���̃|�C���^
//	������
//			�O���f�[�^�̌��ɂ�BER�G���R�[�h���ꂽ�f�[�^������ƃ_���B
//==============================================================
Encryption*	PKCS7::Get_Encryption(unsigned int mode)
{
		__m128i	IV	= cRandom->get__m128i();

	Encryption*	cCE;

	//�Í��A���S���Y�������p���[�h�̐ݒ�
	switch(mode){
		//�ǉ��̈Í��A���S���Y��������ꍇ�́A�����ɒǉ��B
		//DES-CBC
		case(1):
			cDES_CBC.Set_DES(IV.m128i_i64[0]);
			cCE = &cDES_CBC;
			break;
		//DES-EDE3-CBC
		case(2):
			cTDES_CBC.Set_DES(IV.m128i_i64[0]);
			cCE = &cTDES_CBC;
			break;
		//AES-CBC-128
		case(3):
			cAES_CBC128.Set_AES(IV);
			cCE = &cAES_CBC128;
			break;
		//AES-CBC-192
		case(4):
			cAES_CBC192.Set_AES(IV);
			cCE = &cAES_CBC192;
			break;
		//AES-CBC-256
		default:
			cAES_CBC256.Set_AES(IV);
			cCE = &cAES_CBC256;
			break;
	}

	return(cCE);
}

