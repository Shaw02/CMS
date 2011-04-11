#pragma once
#include "../BER_Input.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PKCS8_Input :
	public BER_Input,
	public PrivateKeyInfo
{
public:
	//PrivateKeyInfo���̓|�C���^�[�ŕۑ����Ă���̂ŁA
	//���������ɒu���B
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
