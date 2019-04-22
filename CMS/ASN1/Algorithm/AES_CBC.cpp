#include "StdAfx.h"
#include "AES_CBC.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
AES_CBC::AES_CBC(const char _strName[]):
	AES(_strName)
{
	mode	= CBC;
}
//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
AES_CBC::~AES_CBC(void)
{
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	AES_CBC::SetIV(void *data)
{
	vector = _mm_load_si128((__m128i*)data);
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	AES_CBC::initIV()
{
	vector = _mm_loadu_si128((__m128i *)IV.strValue.c_str());
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			void *data		平文
//	●返値
//			無し
//==============================================================
void	AES_CBC::encrypt(void *data)
{
	__m128i	temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)data), vector));

	vector = temp;
	_mm_store_si128((__m128i*)data, temp);

}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			void *data		暗号文
//	●返値
//			無し
//==============================================================
void	AES_CBC::decrypt(void *data)
{
	__m128i	temp = _mm_xor_si128(InvCipher(_mm_load_si128((__m128i*)data)), vector);

	vector	= _mm_load_si128((__m128i*)data);
	_mm_store_si128((__m128i*)data, temp);

}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	●引数
//			__m128i		_xmm_IV		初期化ベクタIV
//	●返値
//			無し
//==============================================================
void	AES_CBC::Set_AES(__m128i _xmm_IV)
{
	//ASN.1の定義
	Set();
	vector = _xmm_IV;	//	SetIV()と同じ意味。
	IV.Set(_xmm_IV.m128i_i8,sizeof(_xmm_IV));
	Set_Construct(&IV);
}
//==============================================================
//			平文の入力
//--------------------------------------------------------------
//	●引数
//			void			*data	平文
//			unsigned int	iSize	平文のサイズ
//	●返値
//			無し
//==============================================================
void	AES_CBC::encipher(void *data,unsigned int iSize)
{
	__m128i				temp;
	__m128i				_vector		= vector;

	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	while(n < iSize){
		temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector));
		_mm_store_si128((__m128i*)&cData[n], temp);
		_vector = temp;
		n	+=	szBlock;
	}
	vector = _vector;

}
//==============================================================
//			平文の入力（最終）
//--------------------------------------------------------------
//	●引数
//			void			*data	平文
//			unsigned	int	iSize	平文のサイズ
//	●返値
//						int			Paddingとして追加したサイズ
//==============================================================
int		AES_CBC::encipher_last(void *data,unsigned int iSize)
{
	__m128i				temp;
	__m128i				_vector		= vector;

	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	unsigned	int		ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//暗号（最終ブロック直前まで）
	while(iSize >= szBlock){
		temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector));
		_mm_store_si128((__m128i*)&cData[n], temp);
		_vector = temp;
		n		+= szBlock;
		iSize	-= szBlock;
	}

	//Padding処理(PKCS#7)を実施
	ptPadding	= n + ((n%szBlock)?-1:szBlock-1);
	cPadData	= szBlock - iSize;
	cntPadData	= cPadData;
	do{
		cData[ptPadding] = cPadData;
		ptPadding--;
		cntPadData--;
	} while(cntPadData>0);

	//暗号（最終）
	if(iSize == szBlock){
		temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector));
		_mm_store_si128((__m128i*)&cData[n], temp);
		_vector = temp;
		n		+= szBlock;
	}
	temp = Cipher(_mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector));
	_mm_store_si128((__m128i*)&cData[n], temp);
	vector = temp;			//元のメンバー変数に入れる。
//	n		+= szBlock;		//これはいらん。

	return(cPadData);
}
//==============================================================
//			暗号文の入力
//--------------------------------------------------------------
//	●引数
//			void			*data	暗号文
//			unsigned int	iSize	暗号文のサイズ
//	●返値
//			無し
//==============================================================
void	AES_CBC::decipher(void *data,unsigned int iSize)
{
	__m128i				temp;

	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	if((iSize >= szBlock * 4) && (aesni == true)){
		while(n < iSize){
			vector = InvCipher_CBC4((__m128i*)&cData[n], vector);
			n	+=	szBlock * 4;
		}
	}

	while(n < iSize){
		temp = _mm_xor_si128(InvCipher(_mm_load_si128((__m128i*)&cData[n])), vector);
		vector	= _mm_load_si128((__m128i*)&cData[n]);
		_mm_store_si128((__m128i*)&cData[n], temp);
		n	+=	szBlock;
	}

}
//==============================================================
//			暗号文の入力（最終）
//--------------------------------------------------------------
//	●引数
//			void			*data	暗号文
//			unsigned	int	iSize	暗号文のサイズ
//	●返値
//						int	1～szBlock	Paddingデータ
//							-1			Paddingが異常
//==============================================================
int		AES_CBC::decipher_last(void *data,unsigned int iSize)
{
	__m128i				temp;

	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//復号
	if(aesni == true){
		while(iSize > szBlock * 4){
			vector = InvCipher_CBC4((__m128i*)&cData[n], vector);
			n		+= szBlock * 4;
			iSize	-= szBlock * 4;
		}
	}

	while(iSize > 0){
		temp = _mm_xor_si128(InvCipher(_mm_load_si128((__m128i*)&cData[n])), vector);
		vector	= _mm_load_si128((__m128i*)&cData[n]);
		_mm_store_si128((__m128i*)&cData[n], temp);
		n		+= szBlock;
		iSize	-= szBlock;
	}

	//最後のBlockは、Paddingを含む。
	n--;
	cPadData	= cData[n];
	cntPadData	= cPadData;

	//Paddingのチェック
	do{
		if(cData[n] != cPadData){	return(-1);	}
		n--;
		cntPadData--;
	} while(cntPadData>0);

	return(cPadData);
}
