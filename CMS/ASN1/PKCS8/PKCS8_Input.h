#pragma once
#include "../BER_Input.h"
#include "PKCS8.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PKCS8_Input :
	public BER_Input,
	public PKCS8
{
public:
	//基底クラスである"PrivateKeyInfo"では、
	//ポインターで保存しているので、こっち側に置く。
	ObjectIdentifier		Algorithm;

public:
	PKCS8_Input(const char*	strFileName,const char _strName[]="PKCS#8");
	~PKCS8_Input(void);

	void	Get_PrivateKeyInfo(void);
	void	Get_PrivateKey(
				unsigned	char*		_key,
				unsigned	int			_szKey);
	void	Get_PrivateKey_with_check(
				AlgorithmIdentifier*	_algorithm,
				unsigned	char*		_key,
				unsigned	int			_szKey);
};
