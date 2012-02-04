#include "StdAfx.h"
#include "PKCS7.h"


	//暗号
	__declspec(align(16))	DES_CBC			PKCS7::cDES_CBC;
	__declspec(align(16))	DES_EDE3_CBC	PKCS7::cTDES_CBC;
	__declspec(align(16))	AES_CBC128		PKCS7::cAES_CBC128;		//SIMDを使う関係で、
	__declspec(align(16))	AES_CBC192		PKCS7::cAES_CBC192;		//staticに置く必要あり。
	__declspec(align(16))	AES_CBC256		PKCS7::cAES_CBC256;		//(__declspec(align(16)))

	//ハッシュ
	SHA1			PKCS7::cSHA1;			//SHAハッシュ
	SHA224			PKCS7::cSHA224;			//SHAハッシュ
	SHA256			PKCS7::cSHA256;			//SHAハッシュ

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS7::PKCS7(const char _strName[]):
	ContentInfo(_strName),
	cHMAC_SHA1(&cSHA1),
	cHMAC_SHA224(&cSHA224),
	cHMAC_SHA256(&cSHA256)
{
}
//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS7::~PKCS7(void)
{
}
//==============================================================
//		
//--------------------------------------------------------------
//	●引数
//				type	データタイプ
//	●返値
//				無し
//==============================================================
void	PKCS7::Set_Type(unsigned int type)
{
	static	unsigned	int		oid_pkcs7[]	=	{1,2,840,113549,1,7,type};

	Set(oid_pkcs7, sizeof(oid_pkcs7)/sizeof(int));
}
//==============================================================
//				暗号モジュールの取得
//--------------------------------------------------------------
//	●引数
//			unsigned int mode	利用する暗号
//	●返値
//			Encryption*			暗号モジュールのポインタ
//	●注意
//			外部データの後ろにもBERエンコードされたデータがあるとダメ。
//==============================================================
Encryption*	PKCS7::Get_Encryption(unsigned int mode)
{
		__m128i	IV	= cRandom->get__m128i();

	Encryption*	cCE;

	//暗号アルゴリズム＆利用モードの設定
	switch(mode){
		//追加の暗号アルゴリズムがある場合は、ここに追加。
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

