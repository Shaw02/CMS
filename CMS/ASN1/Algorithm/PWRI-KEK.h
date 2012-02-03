#pragma once
#include "Encryption.h"

//======================================================================
//					PWRI
//======================================================================
//	Reference:
//	RFC 5652		Cryptographic Message Syntax (CMS)
//	RFC 3211		Password-based Encryption for CMS
//======================================================================
//
//	本プログラムは、パスワードによるKey Wrapを実施する為のクラスです。
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.11. 9	初版
//======================================================================
/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PWRI_KEK :
	public Encryption
{
public:
	static	unsigned	int		oid[];

			Encryption*				EncryptionAlgorithm;

	//アルゴリズム
	static	DES_CBC					ke_DES_CBC;
	static	DES_EDE3_CBC			ke_TDES_CBC;
	static	AES_CBC128				ke_AES_CBC128;		//SIMDを使う関係で、
	static	AES_CBC192				ke_AES_CBC192;		//staticに置く必要あり。
	static	AES_CBC256				ke_AES_CBC256;		//(__declspec(align(16)))

	//Wrap用
	string	strKey;
	string	strEncrptedKey;

//--------------
//関数
					PWRI_KEK(const char _strName[]="PWRI-KEK");
					~PWRI_KEK(void);

			void	Set_PWRI_KEK(unsigned int mode, __m128i IV);
		Encryption*	PWRI_KEK::Get_Encryption(unsigned int mode, __m128i IV);

			void	Set_Key(void *key);							//暗号鍵 設定
			void	Clear_Key();								//鍵Zero化
//			void	init(){};									//初期化

			//Key Wrap用
			int		KeyWrap(void *KEK,unsigned int szKEK);	//
			int		KeyUnWrap(void *data,unsigned int szData);	//
			void*	GetKey(){return((void *)strKey.c_str());};
			void*	GetEncrptedKey(){return((void *)strEncrptedKey.c_str());};
};
