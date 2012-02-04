#include "StdAfx.h"
#include "PKCS7_3_Output.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS7_3_Output::PKCS7_3_Output(const char*	strFileName):
	PKCS7_Output(strFileName)
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
PKCS7_3_Output::~PKCS7_3_Output(void)
{
}
//==============================================================
//				オブジェクトの設定
//--------------------------------------------------------------
//	●引数
//			ObjectIdentifier*		_type		暗号文のタイプ
//			Encryption*				_algorithm	暗号アルゴリズム
//			unsigned	int			_szContent	暗号文のサイズ（実体はとりあえず外部に）
//	●返値
//			無し
//	●処理
//			(1)	object "EncryptedData" を設定する。
//			(2)	Context[0]に、設定したobject "EncryptedData" を格納する。
//			(3) object "ContentInfo" （※this class）を設定する。
//==============================================================
void	PKCS7_3_Output::Set_EnvelopedData(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm, 
			unsigned	int			_szContent)
{
	//------
	//処理
	enveloped_data.Set(_type, _algorithm, _szContent);
	context.Set_Construct(&enveloped_data);		//ContentInfoクラスのmember
	Set_Type(EnvelopedData_type);
}
//==============================================================
//				暗号モジュールと、暗号鍵の準備
//--------------------------------------------------------------
//	●引数
//		unsigned	int		mode		使用するコンテンツ暗号
//	●返値
//		無し
//	●処理
//		暗号モジュールを用意する。
//		初期化ベクタIV, コンテンツ用暗号鍵CEK（セッション鍵）を、乱数で作成する。
//==============================================================
void	PKCS7_3_Output::MakeEncryption(unsigned int		mode)
{
	unsigned	char*	_CEK;

	//------------------
	//暗号モジュールの取得
	cCE = Get_Encryption(mode);

	//------------------
	//セッション鍵は乱数より自動生成
	_CEK	= new unsigned char [(cCE->szKey<32)?32:cCE->szKey];
	cRandom->get256(_CEK);
	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;
}

//==============================================================
//				受信者情報の追加（受信者は、パスワード）
//--------------------------------------------------------------
//	●引数
//		string*				strPassword		パスワード
//		unsigned	int		count			PBKDF2関数に設定する繰り返し回数
//		unsigned	int		mode			使用する鍵暗号
//	●返値
//		無し。
//	●処理
//		パスワードから鍵暗号化鍵KEKを導出し、セッション鍵をラップする。
//==============================================================
void	PKCS7_3_Output::AddRecipient(
			string*					strPassword,
			unsigned int			count,
			unsigned int			mode)
{
	//------------------
	//鍵導出
	enveloped_data.recipientInfos.AddRecipient(strPassword, &CEK, &cHMAC_SHA256, count, mode);
}
//==============================================================
//				暗号化
//--------------------------------------------------------------
//	●引数
//		FileInput*			f_Plain		平文
//		ObjectIdentifier*	contentType	平文のタイプ
//	●返値
//		無し
//	●処理
//		MakeEncryption()で設定した暗号モジュール（とセッション鍵）で、
//		コンテンツ"f_Plain"を暗号化し、ファイル出力する。
//		メンバー変数"recipientInfos"には、受信者情報が入っている事。
//==============================================================
void	PKCS7_3_Output::encrypt(
			FileInput*			f_Plain,
			ObjectIdentifier*	contentType)
{

	//------------------
	//PKCS#7-3 のオブジェクト作成
	Set_EnvelopedData(contentType, cCE, f_Plain->GetSize());

	//------------------
	//暗号ファイルの出力

	//暗号文本体まで
	write_header();

	//暗号文本体
	enveloped_data.encryptedContentInfo.encrypt((unsigned char*)CEK.strValue.c_str(), f_Plain, this);
}
