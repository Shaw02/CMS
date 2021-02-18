#include "StdAfx.h"
#include "HMAC.h"

//==============================================================
//			コンストラクタ
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
HMAC::HMAC(Digest* _cHash, const char _strName[]):
	AlgorithmIdentifier(_strName),
	cHash(_cHash)
{
	//計算用のバッファ確保
	Kipad		= new char[cHash->szBlock];
	Kopad		= new char[cHash->szBlock + cHash->szHash];
}
//==============================================================
//			デストラクタ
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
HMAC::~HMAC(void)
{
	//計算用のバッファ開放
	delete	Kipad;
	delete	Kopad;
}
//==============================================================
//			鍵のセット
//--------------------------------------------------------------
//	●引数
//		void*				Key		鍵
//		size_t				szKey	鍵のサイズ
//	●返値
//			無し
//	●備考
//			PBKDF2等で、何回も同じ処理をするのは無駄の為
//==============================================================
void	HMAC::SetKey(void* Key, size_t szKey)
{
	//頻度にアクセスするので、レジスタに入れる。
			Digest*	_cHash	=	cHash;				//ハッシュ関数のポインタ
	const	size_t	szBlock =	_cHash->szBlock;	//ハッシュ関数の入力ブロック長
	const	size_t	szHash	=	_cHash->szHash;		//ハッシュ関数の出力長
			char*	_Kipad	=	Kipad;				//最適化でレジスタに入れて貰う。
			char*	_Kopad	=	Kopad;				//

	//------------
	//鍵の0x00Padding
	{
		//変数定義
		const	char*	cKey	= (char *)Key;

		//Padding実施
		if(szKey > szBlock){
			_cHash->CalcHash(_Kipad, Key, szKey);
			szKey = szHash;
			memcpy((char*)_Kopad,(char*)_Kipad,szKey);
		} else {
			memcpy(_Kipad,Key,szKey);
			memcpy(_Kopad,Key,szKey);
		}
		memset(&_Kipad[szKey],0x00,szBlock - szKey);
		memset(&_Kopad[szKey],0x00,szBlock - szKey);
	}

	//------------
	//ipad ＆ opad で排他的論理和した鍵を作成
	{
		//変数定義
						size_t	i		=	0;
		static	const	_mm_i32	_mm_36	= {0x36363636,0x36363636,0x36363636,0x36363636};
		static	const	_mm_i32	_mm_5C	= {0x5C5C5C5C,0x5C5C5C5C,0x5C5C5C5C,0x5C5C5C5C};
						__m128i _mm_temp;	

		//排他的論理和を実施
		while((i + sizeof(__m128i)) < szBlock){
			_mm_storeu_si128((__m128i*)_Kipad, _mm_xor_si128(_mm_loadu_si128((__m128i*)_Kipad) ,_mm_36.m128i));
			_mm_storeu_si128((__m128i*)_Kopad, _mm_xor_si128(_mm_loadu_si128((__m128i*)_Kopad) ,_mm_5C.m128i));
			_Kipad += sizeof(__m128i);
			_Kopad += sizeof(__m128i);
			i += sizeof(__m128i);
		}
		i = szBlock - i;
		_mm_temp	= _mm_xor_si128(_mm_loadu_si128((__m128i*)_Kipad) ,_mm_36.m128i);
		memcpy(_Kipad, &_mm_temp, i);
		_mm_temp	= _mm_xor_si128(_mm_loadu_si128((__m128i*)_Kopad) ,_mm_5C.m128i);
		memcpy(_Kopad, &_mm_temp, i);
	}
}
//==============================================================
//			計算
//--------------------------------------------------------------
//	●引数
//		void*				result	
//		void*				data	メッセージ
//		size_t				szData	メッセージのサイズ
//	●返値
//			無し
//==============================================================
void	HMAC::calc(void* result, void* data, size_t szData)
{
			size_t	i		=	szData;

	//頻度にアクセスするので、レジスタに入れる。
			Digest*	_cHash	=	cHash;				//ハッシュ関数のポインタ
	const	size_t	szBlock =	_cHash->szBlock;	//ハッシュ関数の入力ブロック長
	const	size_t	szHash	=	_cHash->szHash;		//ハッシュ関数の出力長

	//------------
	//計算
	{
		//変数定義
		char*	cData	= (char *)data;

		//1st PASS
		_cHash->init();
		_cHash->add(Kipad);
		while(i>0){
			if(i>=szBlock){
				_cHash->add(cData);
				cData += szBlock;
				i -= szBlock;
			} else {
				_cHash->final(cData,i);
				break;
			}
		}
		_cHash->getHash(&Kopad[szBlock]);

		//2nd PASS
		_cHash->CalcHash(result, Kopad, szBlock + szHash);
	}
}
