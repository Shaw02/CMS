#pragma once
#include "ContentInfo.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PKCS7 :
	public ContentInfo
{
public:
		//暗号
		//oidチェック用に、一つはオブジェクトを作っておく。
static	DES_CBC			cDES_CBC;
static	DES_EDE3_CBC	cTDES_CBC;
static	AES_CBC128		cAES_CBC128;		//SIMDを使う関係で、
static	AES_CBC192		cAES_CBC192;		//staticに置く必要あり。
static	AES_CBC256		cAES_CBC256;		//(__declspec(align(16)))

		//ハッシュ
static	SHA1			cSHA1;			//SHAハッシュ
static	SHA224			cSHA224;		//SHAハッシュ
static	SHA256			cSHA256;		//SHAハッシュ
		HMAC_SHA1		cHMAC_SHA1;
		HMAC_SHA224		cHMAC_SHA224;
		HMAC_SHA256		cHMAC_SHA256;

		PKCS7(const char _strName[]="PKCS#7");
		~PKCS7(void);

		void		Set_Type(unsigned int type);
		Encryption*	Get_Encryption(unsigned int mode);
};
