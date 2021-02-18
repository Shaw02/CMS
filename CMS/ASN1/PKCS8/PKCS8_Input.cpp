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
PKCS8_Input::PKCS8_Input(const char*	strFileName,const char _strName[]):
	BER_Input(strFileName),
	PKCS8(_strName)
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
//			無し
//	●返値
//			無し
//==============================================================
void	PKCS8_Input::Get_PrivateKeyInfo()
{
	size_t	szAlgorithm;
	size_t	ptAlgorithm;

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
		read_Octet_Strings(&privateKey);

		//attributes           [0]  IMPLICIT Attributes OPTIONAL }
}
//==============================================================
//		鍵の取得
//--------------------------------------------------------------
//	●引数
//			unsigned	char*		_key		暗号鍵を格納するポインタ
//						size_t		_szKey		暗号鍵のサイズ（チェック用）
//	●返値
//			無し
//==============================================================
void	PKCS8_Input::Get_PrivateKey(
			unsigned	char*		_key,
						size_t		_szKey)
{
	if(privateKey.strValue.size() != _szKey){
		errPrint("Key",": unmatch key size.");
	}
	memcpy(_key, privateKey.strValue.c_str(), _szKey);
}
//==============================================================
//		鍵の取得（アルゴリズムのチェック付）
//--------------------------------------------------------------
//	●引数
//			algorithmIdentifier*	_algorithm	暗号アルゴリズム
//			unsigned	char*		_key		暗号鍵を格納するポインタ
//						size_t		_szKey		暗号鍵のサイズ（チェック用）
//	●返値
//			無し
//==============================================================
void	PKCS8_Input::Get_PrivateKey_with_check(
			AlgorithmIdentifier*	_algorithm,
			unsigned	char*		_key,
						size_t		_szKey)
{
	unsigned	int		i = 0;

	//ASN.1 構造分析
	Get_PrivateKeyInfo();

	//暗号アルゴリズム　チェック
	do{
		if(_algorithm->algorithm.iValue[i] != Algorithm.iValue[i]){
			errPrint("PrivateKey",": Different encryption algorithm.");
		}
		i++;
	} while(i < _algorithm->algorithm.iValue.size());

	Get_PrivateKey(_key, _szKey);
}
