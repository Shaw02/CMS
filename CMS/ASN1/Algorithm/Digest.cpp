#include "StdAfx.h"
#include "Digest.h"

//==============================================================
//			コンストラクタ
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
Digest::Digest(const char _strName[]):
	AlgorithmIdentifier(_strName)
{
}
//==============================================================
//			デストラクタ
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
Digest::~Digest(void)
{
}
//==============================================================
//			ハッシュ値計算
//--------------------------------------------------------------
//	●引数
//			void	*result		ハッシュ値を格納するアドレス
//			void	*data		入力データのポインタ（64Byte）
//			size_t	n			入力データのサイズ[Byte]
//	●返値
//			無し
//==============================================================
void	Digest::CalcHash(void *result, void *data, size_t iSize)
{
				size_t	i			= iSize;
				size_t	_szBlock	= szBlock;	//頻度に使うのでレジスタに入って貰う。
	unsigned	char*	cData		= (unsigned	char*)data;

	init();

	while(i>0){
		if(i>=_szBlock){
			add(cData);
			cData += _szBlock;
			i -= _szBlock;
		} else {
			final(cData,i);
			break;
		}
	}

	getHash(result);
}
//==============================================================
//			１ブロック（64Byte）の入力
//--------------------------------------------------------------
//	●引数
//			void *data	計算する１ブロックのポインタ（64Byte）
//	●返値
//			無し
//==============================================================
void	Digest::add(void *data)
{
	calc(data);
	iCountBlock++;
}
//==============================================================
//			最終ブロック（64Byte未満）の入力
//--------------------------------------------------------------
//	●引数
//			void	*data		計算する１ブロックのポインタ（64Byte未満）
//			size_t	n			ブロックのサイズ[Byte]
//	●返値
//			無し
//	●返値
//			デフォルトは、MD5, SHA-1, SHA-2用　共用
//==============================================================
void	Digest::final(void *data, size_t iSize)
{
				size_t	i = 0;

	unsigned	__int64		iTotalSize	= ((iCountBlock*64)+iSize)*8;
	unsigned	char*		cData		= (unsigned char*)data;

	//頻度に使うのでレジスタに入って貰う。
	unsigned	char*		_M			= M;
				size_t		_szBlock	= szBlock;

	//--------------------
	//BlockSizeぴったりだった。
	if(iSize == _szBlock){
		add(data);
		iSize = 0;
	}

	//--------------------
	//配列へ
	else if(iSize>0){
		memcpy(_M, cData, iSize);
		i = iSize;
	}

	_M[i] = 0x80;
	i++;

	//--------------------
	//サイズを書き込めない場合
	if(iSize >= (_szBlock-8)){
		memset(&_M[i],0,_szBlock - i);
		add(_M);
		i = 0;
	}

	//--------------------
	//サイズの所まで、0x00で埋める。
	memset(&_M[i],0,(_szBlock-8)-i);
	i = (_szBlock - 8)-i;

	//--------------------
	//サイズ書き込み。
	_M[_szBlock - 8] = (iTotalSize>>56) & 0xFF;
	_M[_szBlock - 7] = (iTotalSize>>48) & 0xFF;
	_M[_szBlock - 6] = (iTotalSize>>40) & 0xFF;
	_M[_szBlock - 5] = (iTotalSize>>32) & 0xFF;
	_M[_szBlock - 4] = (iTotalSize>>24) & 0xFF;
	_M[_szBlock - 3] = (iTotalSize>>16) & 0xFF;
	_M[_szBlock - 2] = (iTotalSize>>8) & 0xFF;
	_M[_szBlock - 1] = iTotalSize & 0xFF;

	calc(_M);
}
