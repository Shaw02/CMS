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
//		ヘッダー構造チェック
//--------------------------------------------------------------
//	●引数
//			
//	●返値
//			
//==============================================================
unsigned	int		PKCS7_6_Input::Get_EncryptedData(void)
{
	//ContentInfo
	Get_ContentInfo(EncryptedData_type);

		//EnvelopedData
		read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

			//version
			read_Integer(&encrypted_data.version);
			if(encrypted_data.version.iValue != 0){
				error(0);	//未対応のVersion
			}
			encrypted_data.Set_Construct(&encrypted_data.version);

			//encryptedContentInfo
			read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);

				//contentType 
				read_Object_Identifier(&contentType);
				encrypted_data.encryptedContentInfo.Set_Construct(&contentType);

				//EncryptionAlgorithm
				szAlgorithm	= read_TAG_with_Check(BER_Class_General, true, BER_TAG_SEQUENCE);
				ptAlgorithm	= tellg();
				read_Object_Identifier(&Algorithm);
				ptAlgorithmPara	= tellg();
				StreamPointerMove(ptAlgorithm + szAlgorithm);

				//ここに入っているのが、暗号文実体のサイズ
				szEncryptedContent = read_TAG_with_Check(BER_Class_Context, false, 0);
				ptEncryptedContent	= tellg();

		//------
		//処理
		context.Set_Construct(&encrypted_data);		//ContentInfoクラスのmember

	return(szEncryptedContent);
}
//--------------------------------
//	絶対シーク	Algorithm
//--------------------------------
void	PKCS7_6_Input::StreamPointerMove_AlgorithmPara(void)
{
	StreamPointerMove(ptAlgorithmPara);
}
//--------------------------------
//	絶対シーク	EncryptedContent
//--------------------------------
void	PKCS7_6_Input::StreamPointerMove_EncryptedContent(void)
{
	StreamPointerMove(ptEncryptedContent);
}
