#pragma once
#include "AlgorithmIdentifier.h"

//======================================================================
//					Content Encryption Algorithm Identifier
//					Key Encryption Algorithm Identifier
//======================================================================
//	Reference:
//	RFC 5652		Cryptographic Message Syntax (CMS)
//	RFC 3370		Cryptographic Message Syntax (CMS) Algorithms
//======================================================================
//
//	�{�v���O�����́A�Í��E�����̂��߂̊��N���X�ł��B
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.10.26	����
//======================================================================
/****************************************************************/
/*			�萔��`											*/
/****************************************************************/


/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class Encryption :
	public AlgorithmIdentifier
{
public:
	unsigned	int		szBlock;
	unsigned	int		szKey;

//--------------
//�֐�
					Encryption(const char _strName[]="Encryption");
					~Encryption(void);

	virtual	void	Set_Key(void *key){};		//�Í��� �ݒ�
	virtual	void	Clear_Key(){};				//�Í��� Zero��
	virtual	void	init(){};					//�Í�������IV�ŏ�����
	virtual	void	encrypt(void *data){encrypt_ecb(data);};	//�Í�
	virtual	void	decrypt(void *data){decrypt_ecb(data);};	//����
	virtual	void	encrypt_ecb(void *data){};	//�Í� ECB Mode
	virtual	void	decrypt_ecb(void *data){};	//���� ECB Mode
	virtual	void	SetIV(void *data){};		//IV�ݒ�	

	//For Content Encryption
	virtual	void	encipher(void *data,unsigned int iSize);
	virtual	void	decipher(void *data,unsigned int iSize);
	virtual	int		encipher_last(void *data,unsigned int iSize);
	virtual	int		decipher_last(void *data,unsigned int iSize);

	//For Key Encryption (Key Wrap)
	virtual	int		KeyWrap(void *CEK,unsigned int szCEK){return(0);};	//
	virtual	int		KeyUnWrap(void *data,unsigned int szData){return(0);};	//
	virtual	void*	GetKey(){return(0);};
	virtual	void*	GetEncrptedKey(){return(0);};
};
