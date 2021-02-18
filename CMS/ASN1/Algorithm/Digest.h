#pragma once
#include "AlgorithmIdentifier.h"

//======================================================================
//					Digest Algorithm Identifier
//======================================================================
//	Reference:
//	RFC 5652		Cryptographic Message Syntax (CMS)
//	RFC 3370		Cryptographic Message Syntax (CMS) Algorithms
//======================================================================
//
//	本プログラムは、ハッシュを算出するための基底クラスです。
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011. 1.17	初版
//======================================================================
/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class Digest :
	public AlgorithmIdentifier
{
public:
				size_t	iCountBlock;		//Block数のカウント
				size_t	szBlock;
				size_t	szHash;

	unsigned	char*	M;					//Padding用


	Digest(const char _strName[]="Digest");
	~Digest(void);

			void	CalcHash(void *result, void *data, size_t iSize);

	virtual	void	init(void){};
			void	add(void *data);
	virtual	void	final(void *data, size_t iSize);	//関数によりPaddingが異なるかもしれない。
	virtual	void	getHash(void *result){};

	virtual	void	calc(void *data){};
};
