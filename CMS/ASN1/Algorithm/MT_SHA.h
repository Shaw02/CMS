#pragma once
#include "MT.h"

//======================================================================
//					Mersenne Twister with SHA-256
//======================================================================
//
//	本プログラムは、疑似乱数"Mersenne Twister"の出力に、
//	更に、暗号学的ハッシュ関数である"SHA-256"を通し、
//	暗号論的擬似乱数生成器と同等の乱数を実現します。
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	注意：
//		乱数の種は、高いエントロピー（より多い情報量）を持つ、
//		無作為情報源が得られた値を使用して下さい。
//			例：	電源起動時からの、CPUの経過クロック数
//					HDDのシーク時間
//					etc..
//
//		※	ゲーム等では現在時刻を乱数の種にする事が多いですが、
//			セキュリティの世界では、お勧めしません。
//			処理した時間が判明した場合、乱数を再現できてしまい、
//			容易な攻撃が可能になってしまいます。
//
//======================================================================
/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class MT_SHA :
	public MT
{
public:
	SHA256	cSHA;
	//ハッシュ計算用のバッファ
	union {
		unsigned	char	c[	(SHA_BlockSize)];
		unsigned	int		i[	(SHA_BlockSize/sizeof(int))];
		unsigned	__int64	i64[(SHA_BlockSize/sizeof(__int64))];
					__m128i	xmm[(SHA_BlockSize/sizeof(__m128i))];
	} __declspec(align(16)) cHashBuff;				//ハッシュ計算用バッファ（暗号のパディング用に16Byte余分に。）

	MT_SHA(unsigned long init_key[], unsigned int key_length);
	~MT_SHA(void);

	void	generate(void);
	int		get_int(void);
	__int64	get_int64(void);
	void	get256(void *result);
	__m128i	get__m128i(void);
};
