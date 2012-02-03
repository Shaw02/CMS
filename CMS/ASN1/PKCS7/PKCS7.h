#pragma once
#include "ContentInfo.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PKCS7 :
	public ContentInfo
{
public:
		//�Í�
		//oid�`�F�b�N�p�ɁA��̓I�u�W�F�N�g������Ă����B
static	DES_CBC			cDES_CBC;
static	DES_EDE3_CBC	cTDES_CBC;
static	AES_CBC128		cAES_CBC128;		//SIMD���g���֌W�ŁA
static	AES_CBC192		cAES_CBC192;		//static�ɒu���K�v����B
static	AES_CBC256		cAES_CBC256;		//(__declspec(align(16)))

		//�n�b�V��
static	SHA1			cSHA1;			//SHA�n�b�V��
static	SHA224			cSHA224;		//SHA�n�b�V��
static	SHA256			cSHA256;		//SHA�n�b�V��
		HMAC_SHA1		cHMAC_SHA1;
		HMAC_SHA224		cHMAC_SHA224;
		HMAC_SHA256		cHMAC_SHA256;

		PKCS7(const char _strName[]="PKCS#7");
		~PKCS7(void);

		void		Set_Type(unsigned int type);
		Encryption*	Get_Encryption(unsigned int mode);
};
