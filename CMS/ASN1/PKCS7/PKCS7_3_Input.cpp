#include "StdAfx.h"
#include "PKCS7_3_Input.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS7_3_Input::PKCS7_3_Input(const char*	strFileName):
	PKCS7_Input(strFileName)
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
PKCS7_3_Input::~PKCS7_3_Input(void)
{
}
//==============================================================
//		【ファイル読み込み】EnvelopedData
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	PKCS7_3_Input::Get_EnvelopedData()
{
	//ContentInfo
	read_ContentInfo(EnvelopedData_type);

	//EnvelopedData
	ptEncryptedContent = read_EnvelopedData(&enveloped_data);
}
//==============================================================
//				暗号化
//--------------------------------------------------------------
//	●引数
//			FileOutput*			f_Plain			平文ファイル
//	●返値
//			ObjectIdentifier*	_contentType	
//	●処理
//			暗号鍵（*.Key）ファイルを暗号鍵にして暗号化
//==============================================================
void	PKCS7_3_Input::decrypt(
			FileOutput*			f_Plain)
{
	int	iResult;

	//暗号文本体
	StreamPointerMove(ptEncryptedContent);
	iResult = enveloped_data.encryptedContentInfo.decrypt((unsigned char*)CEK.strValue.c_str(), this, f_Plain);

	if(iResult != 0){
		errPrint("Decrypt",": Content-Encryption-Key may be different.");
	}
}
