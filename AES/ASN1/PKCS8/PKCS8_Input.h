#pragma once
#include "../BER_Input.h"

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class PKCS8_Input :
	public BER_Input,
	public PrivateKeyInfo
{
public:
	//PrivateKeyInfo側はポインターで保存しているので、
	//こっち側に置く。
	ObjectIdentifier		Algorithm;
	unsigned	int			ptKey;
	unsigned	int			szKey;

public:
	PKCS8_Input(const char*	strFileName);
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
