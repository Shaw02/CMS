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
/*			定数定義											*/
/****************************************************************/

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PWRI_KEK :
	public Encryption
{
public:
//--------------
//変数

/*
PWRI_KEK-params ::= SEQUENCE {
  keyWrapAlgorithm	AlgorithmIdentifier
}
*/
	static	unsigned	int		oid[];

			Encryption*				keyWrapAlgorithm;

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
		Encryption*	Get_Encryption(unsigned int mode, __m128i IV);

			void	Set_Key(void *key);							//暗号鍵 設定
			void	Clear_Key();								//鍵Zero化
//			void	init(){};									//初期化

			//Key Wrap用
			size_t	KeyWrap(void *KEK,size_t szKEK);	//
			size_t	KeyUnWrap(void *data,size_t szData);	//
			void*	GetKey(){return((void *)strKey.c_str());};
			void*	GetEncrptedKey(){return((void *)strEncrptedKey.c_str());};
};
