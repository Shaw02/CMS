#pragma once
#include "AlgorithmIdentifier.h"

//======================================================================
//					Content Encryption Algorithm Identifier
//					Key Encryption Algorithm Identifier
//======================================================================
//	Reference:
//	RFC 5652		Cryptographic Message Syntax (CMS)
//	RFC 3370		Cryptographic Message Syntax (CMS) Algorithms
//======================================================================
//
//	本プログラムは、暗号・復号のための基底クラスです。
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.10.26	初版
//======================================================================
/****************************************************************/
/*			定数定義											*/
/****************************************************************/


/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class Encryption :
	public AlgorithmIdentifier
{
public:
	size_t	szBlock;
	size_t	szKey;

//--------------
//関数
					Encryption(const char _strName[]="Encryption");
					~Encryption(void);

	virtual	void	Set_Key(void *key){};		//暗号鍵 設定
	virtual	void	Clear_Key(){};				//暗号鍵 Zero化
	virtual	void	init(){};					//暗号を鍵とIVで初期化
	virtual	void	encrypt(void *data){encrypt_ecb(data);};	//暗号
	virtual	void	decrypt(void *data){decrypt_ecb(data);};	//復号
	virtual	void	encrypt_ecb(void *data){};	//暗号 ECB Mode
	virtual	void	decrypt_ecb(void *data){};	//復号 ECB Mode
	virtual	void	SetIV(void *data){};		//IV設定	

	//For Content Encryption
	virtual	void	encipher(void *data,size_t iSize);
	virtual	void	decipher(void *data,size_t iSize);
	virtual	int		encipher_last(void *data,size_t iSize);
	virtual	int		decipher_last(void *data,size_t iSize);

	//For Key Encryption (Key Wrap)
	virtual	size_t	KeyWrap(void *CEK,size_t szCEK){return(0);};	//
	virtual	size_t	KeyUnWrap(void *data,size_t szData){return(0);};	//
	virtual	void*	GetKey(){return(0);};
	virtual	void*	GetEncrptedKey(){return(0);};
};
