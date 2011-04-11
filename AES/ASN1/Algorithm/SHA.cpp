#include "StdAfx.h"
#include "SHA.h"

//==============================================================
//			コンストラクタ
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
SHA::SHA(void)
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
SHA::~SHA(void)
{
}
//==============================================================
//			ハッシュ値計算
//--------------------------------------------------------------
//	●引数
//			void *result	ハッシュ値を格納するアドレス
//			void *data		入力データのポインタ（64Byte）
//			unsigned int n	入力データのサイズ[Byte]
//	●返値
//			無し
//==============================================================
void	SHA::CalcHash(void *result, void *data, unsigned int iSize)
{
	unsigned	int		i		= iSize;
	unsigned	int		ptData	= 0;
	unsigned	char*	cData	= (unsigned	char*)data;

	init();

	while(i>0){
		if(i>=SHA_BlockSize){
			add(&cData[ptData]);
			ptData += SHA_BlockSize;
			i -= SHA_BlockSize;
		} else {
			final(&cData[ptData],i);
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
void	SHA::add(void *data)
{
	calc(data);
	iCountBlock++;
}
//==============================================================
//			最終ブロック（64Byte未満）の入力
//--------------------------------------------------------------
//	●引数
//			void *data		計算する１ブロックのポインタ（64Byte未満）
//			unsigned int n	ブロックのサイズ[Byte]
//	●返値
//			無し
//==============================================================
void	SHA::final(void *data,unsigned int iSize)
{
	unsigned	char		M[SHA_BlockSize];

	unsigned	__int64		iTotalSize = ((iCountBlock*64)+iSize)*8;
	unsigned	char*		cData = (unsigned char*)data;

	unsigned	int			i = 0;

	//--------------------
	//BlockSizeぴったりだった。
	if(iSize==SHA_BlockSize){
		add(data);
		iSize = 0;
	}

	//--------------------
	//配列へ
	else if(iSize>0){
		memcpy(M, cData, iSize);
		i = iSize;
	}

	M[i] = 0x80;
	i++;

	//--------------------
	//サイズを書き込めない場合
	if(iSize >= (SHA_BlockSize-8)){
		memset(&M[i],0,SHA_BlockSize-i);
		add(M);
		i = 0;
	}

	//--------------------
	//サイズの所まで、0x00で埋める。
	memset(&M[i],0,(SHA_BlockSize-8)-i);
	i = (SHA_BlockSize-8)-i;

	//--------------------
	//サイズ書き込み。
	M[SHA_BlockSize-8] = (iTotalSize>>56) & 0xFF;
	M[SHA_BlockSize-7] = (iTotalSize>>48) & 0xFF;
	M[SHA_BlockSize-6] = (iTotalSize>>40) & 0xFF;
	M[SHA_BlockSize-5] = (iTotalSize>>32) & 0xFF;
	M[SHA_BlockSize-4] = (iTotalSize>>24) & 0xFF;
	M[SHA_BlockSize-3] = (iTotalSize>>16) & 0xFF;
	M[SHA_BlockSize-2] = (iTotalSize>>8) & 0xFF;
	M[SHA_BlockSize-1] = iTotalSize & 0xFF;

	calc(M);
}
