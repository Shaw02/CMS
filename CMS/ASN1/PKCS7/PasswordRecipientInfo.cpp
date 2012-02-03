#include "StdAfx.h"
#include "PasswordRecipientInfo.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PasswordRecipientInfo::PasswordRecipientInfo(const char _strName[]):
	Sequence(_strName),
	keyDerivationAlgorithm(0)
{
}

//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//	●注意
//				keyDerivationはここで開放する。
//==============================================================
PasswordRecipientInfo::~PasswordRecipientInfo(void)
{
	delete	keyDerivation;
}

//==============================================================
//				オブジェクトの設定
//--------------------------------------------------------------
//	●引数
//			AlgorithmIdentifier*	_keyDerivation	鍵導出アルゴリズム
//			Encryption*				_keyEncryption	鍵暗号化アルゴリズム
//	●返値
//			無し
//==============================================================
void	PasswordRecipientInfo::SetInfo(KeyDerivation* _keyDerivation, Encryption* _keyEncryption)
{

	//version CMSVersion,   -- Always set to 0
	version.Set(0);
	Set_Construct(&version);

	//keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
	_keyDerivation->mode = _IMPLICIT;
	keyDerivation = _keyDerivation;
	keyDerivationAlgorithm.Set_Construct(keyDerivation);
	Set_Construct(&keyDerivationAlgorithm);

	//keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
	keyEncryptionAlgorithm = _keyEncryption;
	Set_Construct(keyEncryptionAlgorithm);

	//encryptedKey EncryptedKey }

}
//==============================================================
//				Key Wrap & Set
//--------------------------------------------------------------
//	●引数
//			void*			ptPassword		パスフレーズ
//			unsigned	int	szPassword		パスフレーズのサイズ
//			void*			Key				CEK
//			unsigned	int	szKey			CEKのサイズ
//	●返値
//			void					
//==============================================================
void	PasswordRecipientInfo::SetKey(void* ptPassword, unsigned int szPassword, void* CEK, unsigned int szCEK)
{
	//暗号鍵 for 鍵
	unsigned	char	KEK[32];

	unsigned	int	szECEK;

	//鍵暗号化鍵の導出
	keyDerivation->calc(KEK, ptPassword, szPassword);

	//暗号器に導出した鍵を設定
	keyEncryptionAlgorithm->Set_Key(KEK);

	//コンテンツ暗号化鍵を鍵暗号化鍵でラップ
	szECEK = keyEncryptionAlgorithm->KeyWrap(CEK,szCEK);	//random

	//ラップした鍵をASN.1 BERへ。
	EncryptedKey.Set((char *)keyEncryptionAlgorithm->GetEncrptedKey(),szECEK);
	Set_Construct(&EncryptedKey);
}