#include "StdAfx.h"
#include "PKCS7_6_Input.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS7_6_Input::PKCS7_6_Input(const char*	strFileName):
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
PKCS7_6_Input::~PKCS7_6_Input(void)
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
void	PKCS7_6_Input::Get_EncryptedData()
{
	//ContentInfo
	read_ContentInfo(EncryptedData_type);

	//EnvelopedData
	ptEncryptedContent = read_EncryptedData(&encrypted_data);
}
//==============================================================
//				暗号モジュールと、暗号鍵の準備
//--------------------------------------------------------------
//	●引数
//			PKCS8_Input*		f_Key			暗号鍵（Keyファイル）
//	●返値
//			無し
//	●処理
//			暗号鍵（*.Key）ファイルを、暗号鍵にする。
//==============================================================
void	PKCS7_6_Input::Set_Encryption(
			PKCS8_Input*		f_KEY)
{
	Encryption*			cCE		= encrypted_data.encryptedContentInfo.contentEncryptionAlgorithm;
	unsigned	char*	_CEK	= new unsigned char [cCE->szKey];

	//------------------
	//鍵取得
	f_KEY->Get_PrivateKey_with_check(cCE, _CEK, cCE->szKey);
	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;

}
//==============================================================
//				暗号化
//--------------------------------------------------------------
//	●引数
//			string*				strPassword		パスワード
//	●返値
//			無し
//	●処理
//			パスワードを暗号鍵にする。
//==============================================================
void	PKCS7_6_Input::Set_Encryption(
			string*				strPassword)
{
	Encryption*			cCE		= encrypted_data.encryptedContentInfo.contentEncryptionAlgorithm;
	unsigned	char*	_CEK	= new unsigned char [cCE->szKey];

	//------------------
	//Password文字列のハッシュ値を、暗号鍵にする。
	cSHA256.CalcHash(_CEK, (void *)strPassword->c_str(), strPassword->length());
	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;

}
//==============================================================
//				暗号化
//--------------------------------------------------------------
//	●引数
//			FileOutput*			f_Plain			平文ファイル
//	●返値
//			無し
//	●処理
//			暗号鍵（*.Key）ファイルを暗号鍵にして暗号化
//==============================================================
void	PKCS7_6_Input::decrypt(
			FileOutput*			f_Plain)
{
	int	iResult;

	//暗号文本体
	StreamPointerMove(ptEncryptedContent);
	iResult = encrypted_data.encryptedContentInfo.decrypt((unsigned char*)CEK.strValue.c_str(), this, f_Plain);

	if(iResult != 0){
		errPrint("Decrypt",": Content-Encryption-Key may be different.");
	}
}
