#include "StdAfx.h"
#include "PWRI-KEK.h"

unsigned	int		PWRI_KEK::oid[] = {1,2,840,113549,1,9,16,3,9};

	DES_CBC			PWRI_KEK::ke_DES_CBC;
	DES_EDE3_CBC	PWRI_KEK::ke_TDES_CBC;
	AES_CBC128		PWRI_KEK::ke_AES_CBC128;		//SIMDを使う関係で、
	AES_CBC192		PWRI_KEK::ke_AES_CBC192;		//staticに置く必要あり。
	AES_CBC256		PWRI_KEK::ke_AES_CBC256;		//(__declspec(align(16)))

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PWRI_KEK::PWRI_KEK(const char _strName[]):
	Encryption(_strName)
{
	Set_oid(oid,sizeof(oid)/sizeof(int));
}
//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
PWRI_KEK::~PWRI_KEK(void)
{
}
//==============================================================
//			Key Zero
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	PWRI_KEK::Clear_Key()
{
	unsigned	i;

	EncryptionAlgorithm->Clear_Key();

	i = strKey.size();
	while(i > 0){
		i--;
		strKey[i] = 0;
	}

	i = strEncrptedKey.size();
	while(i > 0){
		i--;
		strKey[i] = 0;
	}

}
//==============================================================
//			Key Set
//--------------------------------------------------------------
//	●引数
//			void	*key	DES Key (8Byte (7bit * 8 = 56bit))
//	●返値
//			無し
//==============================================================
void	PWRI_KEK::Set_Key(void *key)
{
	EncryptionAlgorithm->Set_Key(key);
}
//==============================================================
//			Key Wrap
//--------------------------------------------------------------
//	●引数
//			void*			data	CEKのポインタ
//			unsigned int	iSize	CEKのサイズ
//			void*			random	乱数値のポインタ
//	●返値
//			int						ラップされたCEKのサイズ
//==============================================================
int	PWRI_KEK::KeyWrap(void *CEK,unsigned int szCEK)
{
	unsigned	char*	cCEK	= (unsigned char*)CEK;

	unsigned	int		szECEK	= szCEK + 4;
	unsigned	int		szKEB	= EncryptionAlgorithm->szBlock;

	unsigned	int	i,j;

				char*	cBuff0;		//暗号化用のバッファ
				char*	cBuff;		//暗号化用のバッファ（アライメント）

	//ラップされたコンテンツ用暗号鍵"CEK"のサイズ
	szECEK  += szKEB - (szECEK % szKEB) - ((szECEK % szKEB)?0:szKEB);

	//暗号用のバッファを確保。アライメントも考慮する。
	cBuff0	= new char [szECEK + szKEB];
	cBuff	= cBuff0 + szKEB - ((int)cBuff0 % szKEB) - (((int)cBuff0 % szKEB)?0:szKEB);

	//コンテンツ用暗号鍵"CEK"のSize
	cBuff[0] = szCEK & 0xFF;

	//Check
	cBuff[1] = 0xFF ^ cCEK[0];
	cBuff[2] = 0xFF ^ cCEK[1];
	cBuff[3] = 0xFF ^ cCEK[2];

	//CEK
	i = 0;
	while(i < szCEK){
		cBuff[4+i] = cCEK[i];
		i++;
	}
	i += 4;

	//Random Padding
	j = 0;
	while(i < szECEK){
		cBuff[i] = cRandom->get_int();
		j++;
		i++;
	}

	//Key Wrap
	EncryptionAlgorithm->init();
	EncryptionAlgorithm->encipher(cBuff, szECEK);
	EncryptionAlgorithm->encipher(cBuff, szECEK);

	strEncrptedKey.resize(szECEK);
	strEncrptedKey.assign(cBuff, szECEK);

	delete	cBuff0;

	return(szECEK);
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			void*			data	ラップされたCEKのポインタ
//			unsigned int	iSize	ラップされたCEKのサイズ
//	●返値
//			int						CEKのサイズ
//==============================================================
int	PWRI_KEK::KeyUnWrap(void *data,unsigned int szData)
{
	unsigned	char*	cData	= (unsigned char*)data;

	unsigned	int		szKEK;
	unsigned	int		szCEK	= EncryptionAlgorithm->szBlock;

	unsigned	int		i;
	unsigned	int		n		= szData / szCEK;		//ブロック数
	unsigned	int		ptData	= szData - (szCEK*2);

	//Using the n-1'th ciphertext block as the IV,
	EncryptionAlgorithm->SetIV(&cData[ptData]);

	//decrypt the n'th ciphertext block.
	ptData += szCEK;
	EncryptionAlgorithm->decrypt(&cData[ptData]);

	//Using the decrypted n'th ciphertext block as the IV,
	EncryptionAlgorithm->SetIV(&cData[ptData]);

	//decrypt the 1st ... n-1'th ciphertext blocks.
	EncryptionAlgorithm->decipher(data, szData-szCEK);

	//Decrypt the inner layer of encryption using the KEK.
	EncryptionAlgorithm->init();
	EncryptionAlgorithm->decipher(data, szData);

	//Check
	if(	((cData[1] ^ 0xFF) == cData[4])
	 &&	((cData[2] ^ 0xFF) == cData[5])
	 &&	((cData[3] ^ 0xFF) == cData[6])){
		szKEK = cData[0];
		strKey.resize(szKEK);
		i = 0;
		while(i < szKEK){
			strKey[i] = cData[4 + i];
			i++;
		}
	} else {
		szKEK = -1;
	}

	return(szKEK);
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			__m128i		_xmm_IV		初期化ベクタIV
//	●返値
//			無し
//==============================================================
void	PWRI_KEK::Set_PWRI_KEK(unsigned int mode, __m128i IV)
{
	//ASN.1の定義
	Set();			//oid
//	EncryptionAlgorithm = _algorithm;
	EncryptionAlgorithm	= Get_Encryption(mode,IV);
	Set_Construct(EncryptionAlgorithm);
}
//==============================================================
//				暗号モジュールの取得
//--------------------------------------------------------------
//	●引数
//			unsigned int mode	利用する暗号
//	●返値
//			Encryption*			暗号モジュールのポインタ
//	●注意
//			外部データの後ろにもBERエンコードされたデータがあるとダメ。
//==============================================================
Encryption*	PWRI_KEK::Get_Encryption(unsigned int mode, __m128i IV)
{

	Encryption*	cKE;

	//暗号アルゴリズム＆利用モードの設定
	switch(mode){
		//追加の暗号アルゴリズムがある場合は、ここに追加。
		//DES-CBC
		case(1):
			ke_DES_CBC.Set_DES(IV.m128i_i64[0]);
			cKE = &ke_DES_CBC;
			break;
		//DES-EDE3-CBC
		case(2):
			ke_TDES_CBC.Set_DES(IV.m128i_i64[0]);
			cKE = &ke_TDES_CBC;
			break;
		//AES-CBC-128
		case(3):
			ke_AES_CBC128.Set_AES(IV);
			cKE = &ke_AES_CBC128;
			break;
		//AES-CBC-192
		case(4):
			ke_AES_CBC192.Set_AES(IV);
			cKE = &ke_AES_CBC192;
			break;
		//AES-CBC-256
		default:
			ke_AES_CBC256.Set_AES(IV);
			cKE = &ke_AES_CBC256;
			break;
	}
	return(cKE);
}
