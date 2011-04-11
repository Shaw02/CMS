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
			AlgorithmIdentifier*	_algorithm, 
			unsigned	int			_szContent)
{
	//------
	//処理
	encrypted_data.Set(_type, _algorithm, _szContent);
	context.Set_Construct(&encrypted_data);		//ContentInfoクラスのmember
	Set_for_PKCS7(EncryptedData_type);
}

//==============================================================
//				ファイルへ
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//	●注意
//			外部データの後ろにもBERエンコードされたデータがあるとダメ。
//==============================================================
void	PKCS7_6_Output::write_header(void)
{
	encodeBER();
	write_BERcode(Get_BERcode(), Get_BERsize());
}