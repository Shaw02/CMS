#pragma once
#include "../BER_Input.h"
#include "PKCS8.h"

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PKCS8_Input :
	public BER_Input,
	public PKCS8
{
public:
	//���N���X�ł���"PrivateKeyInfo"�ł́A
	//�|�C���^�[�ŕۑ����Ă���̂ŁA���������ɒu���B
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
