#include "StdAfx.h"
#include "PKCS7_6_Output.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PKCS7_6_Output::PKCS7_6_Output(const char*	strFileName):
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
PKCS7_6_Output::~PKCS7_6_Output(void)
{
}
//==============================================================
//				オブジェクトの設定
//--------------------------------------------------------------
//	●引数
//			ObjectIdentifier*		_type		暗号文のタイプ
//			AlgorithmIdentifier*	_algorithm	暗号アルゴリズム
//			unsigned	int			_szContent	暗号文のサイズ（実体はとりあえず外部に）
//	●返値
//			無し
//	●処理
//			(1)	object "EncryptedData" を設定する。
//			(2)	Context[0]に、設定したobject "EncryptedData" を格納する。
//			(3) object "ContentInfo" （※this class）を設定する。
//==============================================================
void	PKCS7_6_Output::Set_EncryptedData(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm, 
			unsigned	int			_szContent)
{
	//------
	//処理
	encrypted_data.Set(_type, _algorithm, _szContent);
	context.Set_Construct(&encrypted_data);		//ContentInfoクラスのmember
	Set_Type(EncryptedData_type);
}
//==============================================================
//				暗号モジュールと、暗号鍵の準備
//--------------------------------------------------------------
//	●引数
//			PKCS8_Output*		f_KEY			鍵ファイル
//			unsigned	int		mode			使用するコンテンツ暗号
//	●返値
//			無し
//	●処理
//			暗号鍵は、乱数より生成。
//			暗号鍵（*.Key）ファイルに、暗号鍵を保存する。
//==============================================================
void	PKCS7_6_Output::Set_Encryption(
			PKCS8_Output*		f_KEY,
			unsigned	int		mode)
{
	unsigned	char*	_CEK;

	//------------------
	//暗号モジュールの取得
	cCE = Get_Encryption(mode);

	//------------------
	//鍵は乱数より自動生成
	_CEK	= new unsigned char [(cCE->szKey<32)?32:cCE->szKey];

	cRandom->get256(_CEK);
	CEK.Set((char *)_CEK, cCE->szKey);

	//鍵を*.keyファイルに保存
	f_KEY->Set(cCE, (char *)_CEK, cCE->szKey);
	f_KEY->encodeBER_to_File();

	delete	_CEK;

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
void	PKCS7_6_Output::Set_Encryption(
			PKCS8_Input*		f_KEY)
{
				__m128i	_IV	= cRandom->get__m128i();
	unsigned	char*	_CEK;

	//------------------
	//暗号モジュールと、暗号鍵の準備

	//鍵ファイルで、鍵とアルゴリズムを指定？
	f_KEY->Get_PrivateKeyInfo();

	//暗号アルゴリズム ＆ 暗号利用モードは？
	//追加の暗号アルゴリズムがある場合は、ここに追加。
	if(cDES_CBC.Check_OID(&f_KEY->Algorithm) != -1){
		cDES_CBC.Set_DES(_IV.m128i_i64[0]);
		cCE = &cDES_CBC;
	} else if(cTDES_CBC.Check_OID(&f_KEY->Algorithm) != -1){
		cTDES_CBC.Set_DES(_IV.m128i_i64[0]);
		cCE = &cTDES_CBC;
	} else if(cAES_CBC128.Check_OID(&f_KEY->Algorithm) != -1){
		cAES_CBC128.Set_AES(_IV);
		cCE = &cAES_CBC128;
	} else if(cAES_CBC192.Check_OID(&f_KEY->Algorithm) != -1){
		cAES_CBC192.Set_AES(_IV);
		cCE = &cAES_CBC128;
	} else if(cAES_CBC256.Check_OID(&f_KEY->Algorithm) != -1){
		cAES_CBC256.Set_AES(_IV);
		cCE = &cAES_CBC256;
	} else {
		errPrint("",": Unknown encryption algorithm.");
	}

	//鍵取得
	_CEK	= new unsigned char [cCE->szKey];
	f_KEY->Get_PrivateKey(_CEK, cCE->szKey);
	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;

}
//==============================================================
//				暗号化
//--------------------------------------------------------------
//	●引数
//			string*				strPassword		パスワード
//			unsigned	int		mode			使用するコンテンツ暗号
//	●返値
//	●処理
//==============================================================
void	PKCS7_6_Output::Set_Encryption(
			string*				strPassword,
			unsigned	int		mode)
{
	unsigned	char*	_CEK;
	unsigned	int*	iCEK;
	unsigned	int		i = 0;
	unsigned	int		n;

	//------------------
	//暗号モジュールの取得
	cCE = Get_Encryption(mode);

	//------------------
	//Password文字列のハッシュ値を、暗号鍵にする。
	_CEK	= new unsigned char [(cCE->szKey<32)?32:cCE->szKey];
	iCEK	= (unsigned	int*)_CEK;
	cSHA256.CalcHash(_CEK, (void *)strPassword->c_str(), strPassword->length());
	while(i<8){
		n = iCEK[i];
		iCEK[i] = ((n>>24) & 0xFF) | ((n>>8) & 0xFF00) | ((n & 0xFF00)<<8) | ((n & 0xFF)<<24);
		i++;
	}

	CEK.Set((char *)_CEK, cCE->szKey);
	delete	_CEK;

}
//==============================================================
//				暗号化
//--------------------------------------------------------------
//	●引数
//			FileInput*			f_Plain			平文ファイル
//			ObjectIdentifier*	_contentType	
//	●返値
//	●処理
//			暗号化
//==============================================================
void	PKCS7_6_Output::encrypt(
			FileInput*			f_Plain,
			ObjectIdentifier*	contentType)
{

	//------------------
	//PKCS#7-6 のオブジェクト作成
	Set_EncryptedData(contentType, cCE, f_Plain->GetSize());

	//------------------
	//暗号ファイルの出力

	//暗号文本体まで
	write_header();

	//暗号文本体
	encrypted_data.encryptedContentInfo.encrypt((unsigned char*)CEK.strValue.c_str(), f_Plain, this);
}
