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
	__m128i	temp = _mm_xor_si128(_mm_load_si128((__m128i*)data), vector);

	if(cOpsw->chkAESNI()){
		vector = Cipher_AESNI(temp);
	} else {
		vector = Cipher_SSE2(temp);
	}
	_mm_store_si128((__m128i*)data, vector);
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
	__m128i	_vector	= _mm_load_si128((__m128i*)data);
	__m128i	temp;

	if(cOpsw->chkAESNI()){
		temp = InvCipher_AESNI(_vector);
	} else {
		temp = InvCipher_SSE2(_vector);
	}
	temp	= _mm_xor_si128(temp, vector);
	_mm_store_si128((__m128i*)data, temp);
	vector	= _vector;
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
//			size_t			iSize	平文のサイズ
//	●返値
//			無し
//==============================================================
void	AES_CBC::encipher(void *data,size_t iSize)
{
	__m128i				temp;
	__m128i				_vector		= vector;

	unsigned	char*	cData		= (unsigned	char*)data;

	if(cOpsw->chkAESNI()){
		for(size_t n=0; n<iSize; n+=szBlock){
			temp = _mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector);
			_vector = Cipher_AESNI(temp);
			_mm_store_si128((__m128i*)&cData[n], _vector);
		}
	} else {
		for(size_t n=0; n<iSize; n+=szBlock){
			temp = _mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector);
			_vector = Cipher_SSE2(temp);
			_mm_store_si128((__m128i*)&cData[n], _vector);
		}
	}
	vector = _vector;
}
//==============================================================
//			平文の入力（最終）
//--------------------------------------------------------------
//	●引数
//			void			*data	平文
//			size_t			iSize	平文のサイズ
//	●返値
//			int						Paddingとして追加したサイズ
//==============================================================
int	AES_CBC::encipher_last(void *data,size_t iSize)
{
	__m128i				temp;
	__m128i				_vector		= vector;

	unsigned	char*	cData		= (unsigned	char*)data;
				size_t	n			= 0;

				size_t	ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//暗号（最終ブロック直前まで）
	if(cOpsw->chkAESNI()){
		while(iSize >= szBlock){
			temp = _mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector);
			_vector = Cipher_AESNI(temp);
			_mm_store_si128((__m128i*)&cData[n], _vector);
			n		+= szBlock;
			iSize	-= szBlock;
		}
	} else {
		while(iSize >= szBlock){
			temp = _mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector);
			_vector = Cipher_SSE2(temp);
			_mm_store_si128((__m128i*)&cData[n], _vector);
			n		+= szBlock;
			iSize	-= szBlock;
		}
	}


	//Padding処理(PKCS#7)を実施
	ptPadding	= n + ((n%szBlock)?-1:szBlock-1);
	cPadData	= (unsigned char)(szBlock - iSize);
	cntPadData	= cPadData;
	do{
		cData[ptPadding] = cPadData;
		ptPadding--;
		cntPadData--;
	} while(cntPadData>0);


	//暗号（最終）
	if(cOpsw->chkAESNI()){
		if(iSize == szBlock){
			temp = _mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector);
			_vector = Cipher_AESNI(temp);
			_mm_store_si128((__m128i*)&cData[n], _vector);
			n		+= szBlock;
		}
		temp = _mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector);
		vector = Cipher_AESNI(temp);			//元のメンバー変数に入れる。
	} else {
		if(iSize == szBlock){
			temp = _mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector);
			_vector = Cipher_SSE2(temp);
			_mm_store_si128((__m128i*)&cData[n], _vector);
			n		+= szBlock;
		}
		temp = _mm_xor_si128(_mm_load_si128((__m128i*)&cData[n]), _vector);
		vector = Cipher_SSE2(temp);			//元のメンバー変数に入れる。
	}
	_mm_store_si128((__m128i*)&cData[n], vector);

	return(cPadData);
}
//==============================================================
//			暗号文の入力
//--------------------------------------------------------------
//	●引数
//			void			*data	暗号文
//			size_t			iSize	暗号文のサイズ
//	●返値
//			無し
//==============================================================
void	AES_CBC::decipher(void *data,size_t iSize)
{
	__m128i				temp;
	__m128i				_vector = vector;
	__m128i				__vector;

	unsigned	char*	cData		= (unsigned	char*)data;
				size_t	n			= 0;
				size_t	szBlock_for_SIMD;

	if(cOpsw->chkAESNI()){

#ifdef	_M_X64
		szBlock_for_SIMD = szBlock * 8;
		if(iSize >= szBlock_for_SIMD){
			for(n=0; n<iSize; n+=szBlock_for_SIMD){
				_vector = InvCipher_CBC8((__m128i*)&cData[n], _vector);
			}
		}
#else
		szBlock_for_SIMD = szBlock * 4;
		if(iSize >= szBlock_for_SIMD){
			for(n=0; n<iSize; n+=szBlock_for_SIMD){
				_vector = InvCipher_CBC4((__m128i*) & cData[n], _vector);
			}
		}
#endif

		while(n < iSize){
			__vector	= _mm_load_si128((__m128i*)&cData[n]);
			temp	= InvCipher_AESNI(__vector);
			temp	= _mm_xor_si128(temp, _vector);
			_mm_store_si128((__m128i*)&cData[n], temp);
			_vector	= __vector;
			n	+=	szBlock;
		}
	} else {
		while(n < iSize){
			__vector	= _mm_load_si128((__m128i*)&cData[n]);
			temp	= InvCipher_SSE2(__vector);
			temp	= _mm_xor_si128(temp, _vector);
			_mm_store_si128((__m128i*)&cData[n], temp);
			_vector	= __vector;
			n	+=	szBlock;
		}
	}
	vector = _vector;	//メンバー変数には最後に入れる。
}

//==============================================================
//			暗号文の入力（最終）
//--------------------------------------------------------------
//	●引数
//			void			*data	暗号文
//			size_t			iSize	暗号文のサイズ
//	●返値
//			int			1～szBlock	Paddingデータ
//						-1			Paddingが異常
//==============================================================
int		AES_CBC::decipher_last(void *data,size_t iSize)
{
	__m128i				temp;
	__m128i				_vector = vector;
	__m128i				__vector;

	unsigned	char*	cData		= (unsigned	char*)data;
				size_t	n			= 0;
				size_t	szBlock_for_SIMD;

	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//復号
	if(cOpsw->chkAESNI()){

#ifdef	_M_X64
		szBlock_for_SIMD = szBlock * 8;
		while(iSize > szBlock_for_SIMD){
			_vector = InvCipher_CBC8((__m128i*) & cData[n], _vector);
			n		+= szBlock_for_SIMD;
			iSize	-= szBlock_for_SIMD;
		}
#else
		szBlock_for_SIMD = szBlock * 4;
		while(iSize > szBlock_for_SIMD){
			_vector = InvCipher_CBC4((__m128i*) & cData[n], _vector);
			n		+= szBlock_for_SIMD;
			iSize	-= szBlock_for_SIMD;
		}
#endif

		while(iSize > 0){
			__vector	= _mm_load_si128((__m128i*)&cData[n]);
			temp	= InvCipher_AESNI(__vector);
			temp	= _mm_xor_si128(temp, _vector);
			_mm_store_si128((__m128i*)&cData[n], temp);
			_vector	= __vector;
			n		+= szBlock;
			iSize	-= szBlock;
		}
	} else {
		while(iSize > 0){
			__vector	= _mm_load_si128((__m128i*)&cData[n]);
			temp	= InvCipher_SSE2(__vector);
			temp	= _mm_xor_si128(temp, _vector);
			_mm_store_si128((__m128i*)&cData[n], temp);
			_vector	= __vector;
			n		+= szBlock;
			iSize	-= szBlock;
		}
	}
	vector = _vector;	//メンバー変数には最後に入れる。

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

//==============================================================
//			fips-197	5.3		InvCipher CBC4 (AES-NI)
//--------------------------------------------------------------
//	●引数
//			__m128i*	data		Plain-text 
//			__m128i		vector		now vector
//	●返値
//			__m128i					next vector
//==============================================================
#ifdef	_M_X64
__m128i	AES_CBC::InvCipher_CBC8(__m128i* data, __m128i vector)
#else
__m128i	AES_CBC::InvCipher_CBC4(__m128i* data, __m128i vector)
#endif
{

	__m128i*	_w = (__m128i*)w;

	//Load
	//◆Round (Nr)
	size_t	i		= Nr;
#ifdef	_M_X64
	__m128i	_vector	= data[7];
#else
	__m128i	_vector = data[3];
#endif

	__m128i	tmp		= _w[i];
	__m128i	xdata1	= _mm_xor_si128(data[0],tmp);
	__m128i	xdata2	= _mm_xor_si128(data[1],tmp);
	__m128i	xdata3	= _mm_xor_si128(data[2],tmp);
	__m128i	xdata4	= _mm_xor_si128(data[3],tmp);
#ifdef	_M_X64
	__m128i	xdata5	= _mm_xor_si128(data[4],tmp);
	__m128i	xdata6	= _mm_xor_si128(data[5],tmp);
	__m128i	xdata7	= _mm_xor_si128(data[6],tmp);
	__m128i	xdata8	= _mm_xor_si128(data[7],tmp);
#endif
	i--;

	//◆Round (Nr-1) ～ (1)
	do{
		tmp   = _mm_aesimc_si128(_w[i]);
		xdata1 = _mm_aesdec_si128(xdata1, tmp);
		xdata2 = _mm_aesdec_si128(xdata2, tmp);
		xdata3 = _mm_aesdec_si128(xdata3, tmp);
		xdata4 = _mm_aesdec_si128(xdata4, tmp);
#ifdef	_M_X64
		xdata5 = _mm_aesdec_si128(xdata5, tmp);
		xdata6 = _mm_aesdec_si128(xdata6, tmp);
		xdata7 = _mm_aesdec_si128(xdata7, tmp);
		xdata8 = _mm_aesdec_si128(xdata8, tmp);
#endif
		i--;

	} while(i > 0);

	//◆Round (0)
	// & CBC calc & Store
//	tmp		= _mm_load_si128((__m128i*)&w[i*4]);
	tmp   = _w[i];
#ifdef	_M_X64
	data[7]	= _mm_xor_si128(_mm_aesdeclast_si128(xdata8, tmp), data[6]);
	data[6]	= _mm_xor_si128(_mm_aesdeclast_si128(xdata7, tmp), data[5]);
	data[5]	= _mm_xor_si128(_mm_aesdeclast_si128(xdata6, tmp), data[4]);
	data[4]	= _mm_xor_si128(_mm_aesdeclast_si128(xdata5, tmp), data[3]);
#endif
	data[3]	= _mm_xor_si128(_mm_aesdeclast_si128(xdata4, tmp), data[2]);
	data[2]	= _mm_xor_si128(_mm_aesdeclast_si128(xdata3, tmp), data[1]);
	data[1]	= _mm_xor_si128(_mm_aesdeclast_si128(xdata2, tmp), data[0]);
	data[0]	= _mm_xor_si128(_mm_aesdeclast_si128(xdata1, tmp), vector);

	return(_vector);
}
