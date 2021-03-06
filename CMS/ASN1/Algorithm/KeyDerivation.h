#pragma once
#include "AlgorithmIdentifier.h"

//======================================================================
//					KeyDerivation
//----------------------------------------------------------------------
//	Reference:
//
//======================================================================
//
//	本プログラムは、
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.11.22		初版
//======================================================================
/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class KeyDerivation :
	public AlgorithmIdentifier
{
//--------------
//変数
public:
			unsigned	int		dkLen;		//

//--------------
//関数
public:
	KeyDerivation(const char _strName[]="Key Derivation");
	~KeyDerivation(void);

	virtual	void	calc(void* DK, void* P, unsigned int szP){};
};
