#include "StdAfx.h"
#include "EncryptedContentInfo.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
EncryptedContentInfo::EncryptedContentInfo(const char _strName[]):
	Sequence(_strName),
	encryptedContent(0)
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
EncryptedContentInfo::~EncryptedContentInfo(void)
{
}

//==============================================================
//				オブジェクトの設定
//--------------------------------------------------------------
//	●引数
//			ObjectIdentifier*		_type		暗号文のタイプ
//			Encryption*				_algorithm	暗号アルゴリズム（IVもセットする事）
//			unsigned	int			_szContent	暗号文のサイズ（実体はとりあえず外部に）
//	●返値
//			無し
//==============================================================
void	EncryptedContentInfo::Set(
			ObjectIdentifier*		_type,
			Encryption*				_algorithm,
			unsigned	int			_szContent)
{
	//contentType ContentType
	contentType	= _type;
	Set_Construct(contentType);

	//contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier
	contentEncryptionAlgorithm = _algorithm;
	Set_Construct(contentEncryptionAlgorithm);

	//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
	encryptedContent.Set_ExternalDataSize(_szContent - (_szContent % _algorithm->szBlock) + _algorithm->szBlock);
	Set_Construct(&encryptedContent);

	szContent = _szContent;
}
//==============================================================
//				暗号
//--------------------------------------------------------------
//	●引数
//			unsigned char*	CEK			暗号鍵
//			FileInput*		f_Plain		入力ファイル（平文）
//			FileOutput*		f_Cipher	出力ファイル（暗号文）
//	●返値
//			int				0			正常（これしか返さないけど…）
//							-1			異常
//	●注意
//			これより前のASN.1データは、事前にエンコードしてファイルに出力しておく事。
//			引数"f_Cipher"には、上述の途中までエンコードされたファイルオブジェクトを渡す。
//==============================================================
int		EncryptedContentInfo::encrypt(
			unsigned char*	CEK,
			FileInput*	f_Plain, 
			FileOutput*	f_Cipher)
{
	//暗号用の処理バッファ
	union {
		unsigned	char	c[	(Encrypt_Buff)];
					__m128i	xmm[(Encrypt_Buff/sizeof(__m128i))];
	} static __declspec(align(16)) Buff;

	int		iPad;

	//------------------
	//鍵の設定
	contentEncryptionAlgorithm->Set_Key(CEK);

	//------------------
	//暗号処理
	do{
		//高速化の為、ある程度読み込んで、一気に暗号処理をする。
		f_Plain->read((char *)Buff.c, Encrypt_Buff);

		if(szContent >= Encrypt_Buff){
			contentEncryptionAlgorithm->encipher((char *)Buff.c, Encrypt_Buff);
			f_Cipher->write((char *)Buff.c, Encrypt_Buff);
			szContent -= Encrypt_Buff;
		} else {
			iPad = contentEncryptionAlgorithm->encipher_last((char *)Buff.c, szContent);
			f_Cipher->write((char *)Buff.c, szContent + iPad);
			break;
		}

	} while(1);

	return(0);
}
//==============================================================
//				復号
//--------------------------------------------------------------
//	●引数
//			unsigned char*	CEK			暗号鍵
//			FileInput*		f_Cipherf	入力ファイル（暗号文）
//			FileOutput*		f_Plain		出力ファイル（平文）
//			unsigned int	szContent	サイズ
//	●返値
//			int				0			正常
//							-1			異常
//	●注意
//			これより前のASN.1データは、事前にファイルから入力してデコードしておく事。
//			引数"f_Cipher"のファイル読み込みポインターは、暗号文本体の位置にある事。
//==============================================================
int		EncryptedContentInfo::decrypt(
			unsigned char*	CEK,
			FileInput*		f_Cipher,
			FileOutput*		f_Plain)
{
	//暗号用の処理バッファ
	union {
		unsigned	char	c[	(Encrypt_Buff)];
					__m128i	xmm[(Encrypt_Buff/sizeof(__m128i))];
	} static __declspec(align(16)) Buff;

	int		iPad;

	//------------------
	//鍵の設定
	contentEncryptionAlgorithm->Set_Key(CEK);

	//------------------
	//復号処理
	do {
		//高速化の為、ある程度読み込んで、一気に暗号処理をする。
		f_Cipher->read((char *)Buff.c, Encrypt_Buff);

		if(szContent > Encrypt_Buff){
			contentEncryptionAlgorithm->decipher((char *)Buff.c, Encrypt_Buff);
			f_Plain->write((char *)Buff.c, Encrypt_Buff);
			szContent -= Encrypt_Buff;
		} else {
			iPad = contentEncryptionAlgorithm->decipher_last((char *)Buff.c, szContent);
			if(iPad == -1){
				return(iPad);
			}
			//Paddingデータに基づいてファイル出力
			f_Plain->write((char *)Buff.c, szContent - iPad);
			break;
		}
	} while(1);

	return(0);
}
