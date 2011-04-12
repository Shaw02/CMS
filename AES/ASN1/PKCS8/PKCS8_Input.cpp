#include "StdAfx.h"
#include "PKCS8_Input.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS8_Input::PKCS8_Input(const char*	strFileName):
	BER_Input(strFileName),
	PrivateKeyInfo("PKCS#8 File input")
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
PKCS8_Input::~PKCS8_Input(void)
{
}
//==============================================================
//		ヘッダー構造チェック
//--------------------------------------------------------------
//	●引数
//			unsigned	char	cType	コンテンツタイプ
//	●返値
//			unsigned	int				コンテンツのサイズ
//==============================================================
void	PKCS8_Input::Get_PrivateKeyInfo()
{
	unsigned	int		szAlgorithm;
	unsigned	int		ptAlgorithm;

	//SEQUENCE
	read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

 		//version                   Version,
		read_Integer(&version);
		if(version.iValue != 0){
			error(0);	//未対応のVersion
		}

		//privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
		szAlgorithm	= read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
		ptAlgorithm	= tellg();
		read_Object_Identifier(&Algorithm);		//OIDだけ読む
		StreamPointerMove(ptAlgorithm + szAlgorithm);

		//privateKey                PrivateKey,
		szKey = read_Octet_Strings();		//サイズ
		ptKey = tellg();					//ポインタ

		//attributes           [0]  IMPLICIT Attributes OPTIONAL }
}
//==============================================================
//		ヘッダー構造チェック
//--------------------------------------------------------------
//	●引数
//			algorithmIdentifier*	_algorithm	暗号アルゴリズム
//	●返値
//			unsigned	char*					暗号鍵
//==============================================================
void	PKCS8_Input::Get_PrivateKey(
			unsigned	char*		_key,
			unsigned	int			_szKey)
{
	if(szKey != _szKey){
		errPrint("Key",": unmatch key size.");
	}
	StreamPointerMove(ptKey);
	read((char *)_key, szKey);
}
//==============================================================
//		ヘッダー構造チェック
//--------------------------------------------------------------
//	●引数
//			algorithmIdentifier*	_algorithm	暗号アルゴリズム
//	●返値
//			unsigned	char*					暗号鍵
//==============================================================
void	PKCS8_Input::Get_PrivateKey_with_check(
			AlgorithmIdentifier*	_algorithm,
			unsigned	char*		_key,
			unsigned	int			_szKey)
{
	unsigned	int		i = 0;

	//ASN.1 構造分析
	Get_PrivateKeyInfo();

	//暗号アルゴリズム　チェック
	do{
		if(_algorithm->algorithm.iValue[i] != Algorithm.iValue[i]){
			errPrint("Key",": Different encryption algorithm of mode of key file.");
		}
		i++;
	} while(i < _algorithm->algorithm.iValue.size());

	Get_PrivateKey(_key, _szKey);
}
