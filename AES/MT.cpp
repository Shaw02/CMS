#include "stdafx.h"
#include "mt.h"

//==============================================================
//		
//--------------------------------------------------------------
//	●引数
//		無し
//	●返値
//		無し	
//==============================================================
MT::MT():
	mti(N+1)
{
	//Default seed	スタティック領域に置く。（スタックに置くとmov命令を4つ吐く。）
	static	unsigned	long	init[4]	=	{0x123, 0x234, 0x345, 0x456};

	init_by_array(init, 4);
}
//==============================================================
//		
//--------------------------------------------------------------
//	●引数
//		unsigned long init_key[]	種
//		unsigned int key_length		種の数
//	●返値
//		無し	
//==============================================================
MT::MT(unsigned long init_key[], unsigned int key_length):
	mti(N+1)
{
	init_by_array(init_key, key_length);
}
//==============================================================
//		initializes mt[N] with a seed
//--------------------------------------------------------------
//	●引数
//		unsigned	long	s		種
//	●返値
//		無し	
//==============================================================
void MT::init_genrand(unsigned long s)
{

	unsigned	int	iMT = 0;	//一旦レジスタに入れる。

	mt[iMT++] = s & 0xffffffffUL;

	do{
	//	__asm	prefetchnta	mt[iMT+8]
		_mm_prefetch((const char *)&mt[iMT+4], 0);	//直近の配列を、L1キャッシュにフェッチしておく。
		_mm_prefetch((const char *)&mt[iMT+8], 1);	//そろそろのを、L2キャッシュにフェッチしておく。

		//メモリを使わないで、レジスターだけで計算する。
		//変数"s"には、既に mt[iMT-1]が入っている。
		s = ((unsigned long)1812433253 * (s ^ (s >> 30)) + iMT) & 0xffffffffUL;
	
		//配列変数への書き込みは、この一回だけに。
		mt[iMT++] = s;

	} while (iMT < N);

	mti = iMT;
}

//==============================================================
//		initialize by an array with array-length
//		init_key is the array for initializing keys
//		key_length is its length
//		slight change for C++, 2004/2/26
//--------------------------------------------------------------
//	●引数
//		unsigned long init_key[]	種
//		unsigned int key_length		種の数
//	●返値
//		無し
//==============================================================
void MT::init_by_array(unsigned long init_key[], unsigned int key_length)
{

	//この辺は、レジスター変数になってくれる。
	unsigned	int		iMT		= 0;	
	unsigned	int		iKey	= 0;	
	unsigned	int		k		= ((N>key_length)? N : key_length);
	unsigned	long	r;		//result

	init_genrand(19650218UL);

	r = mt[iMT++];		//ループ内でのメモリ読み込みを無くす為、ここで読んでおく。
						//メモリを何度もアクセスすると、メモリのキャッシュのR/Wが働く為。

	while(k--){
	//	__asm	prefetchnta	mt[iMT+8]
		_mm_prefetch((const char *)&mt[iMT+4], 0);	//直近の配列を、L1キャッシュにフェッチしておく。
	//	_mm_prefetch((const char *)&mt[iMT+8], 1);	//そろそろのを、L2キャッシュにフェッチしておく。

		//メモリを使わないで、レジスターだけで計算する。
		//変数"r"には、既に mt[iMT-1]が入っている。
		r = ((mt[iMT] ^ ((r ^ (r >> 30)) * (unsigned long)1664525)) + init_key[iKey] + iKey) & 0xffffffffUL;

		//配列変数への書き込みは、この一回だけに。
		mt[iMT++] = r;

		if (iMT>=N){
			iMT=1;
//			mt[iMT++] = r;		//変数"r"に入っているので要らない
		}
		iKey++;
		if(iKey>=key_length){iKey=0;}
	};

	k = N-1;
	while(k--){
	//	__asm	prefetchnta	mt[iMT+8]
		_mm_prefetch((const char *)&mt[iMT+4], 0);	//直近の配列を、L1キャッシュにフェッチしておく。
	//	_mm_prefetch((const char *)&mt[iMT+8], 1);	//そろそろのを、L2キャッシュにフェッチしておく。

		//メモリを使わないで、レジスターだけで計算する。
		//変数"r"には、既に mt[iMT-1]が入っている。
		r = ((mt[iMT] ^ ((r ^ (r >> 30)) * (unsigned long)1566083941)) - iMT) & 0xffffffffUL;

		mt[iMT++] = r;		//配列への書き込み。
        if (iMT>=N){
			iMT=1;
//			mt[iMT++] = r;		//変数"r"に入っているので要らない
		}
	};

	mt[0] = 0x80000000UL; /* MSB is 1; assuring non-zero initial array */ 

}

//==============================================================
//		generates a random number on [0,0xffffffff]-interval
//--------------------------------------------------------------
//	●引数
//		無し
//	●返値
//		unsigned long		乱数
//==============================================================
unsigned long MT::genrand_int32(void)
{

	unsigned	int		iMT = mti;	//一旦レジスタに入れる。
	unsigned	long	y;
	unsigned	long	n;

	if(iMT >= N){

		if(iMT >= N+1){		//初期化されていなかったら、初期化する。
			init_genrand(5489);
		}

		iMT		= 0;
		n		= mt[iMT];
		do{
			y = (n & UPPER_MASK);
			n = mt[iMT+1];			//次の値として使う。
			y |= (n & LOWER_MASK);
			mt[iMT] = (mt[iMT+M]) ^ ((y)&1UL ? MATRIX_A : 0) ^ (y >> 1);
			iMT++;
		} while (iMT < N-M);

		do{
			y = (n & UPPER_MASK);
			n = mt[iMT+1];			//次の値として使う。
			y |= (n & LOWER_MASK);
			mt[iMT] = (mt[iMT+M-N]) ^ ((y)&1UL ? MATRIX_A : 0) ^ (y >> 1);
			iMT++;
		} while (iMT < N-1);

			y = (n & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N-1] = (mt[M-1]) ^ ((y)&1UL ? MATRIX_A : 0) ^ (y >> 1);
			iMT = 0;
	}

    /* Tempering */
	y	= mt[iMT++];
	mti	= iMT;

	y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);

    return y;
}
