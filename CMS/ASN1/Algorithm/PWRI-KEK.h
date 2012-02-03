#pragma once
#include "Encryption.h"

//======================================================================
//					PWRI
//======================================================================
//	Reference:
//	RFC 5652		Cryptographic Message Syntax (CMS)
//	RFC 3211		Password-based Encryption for CMS
//======================================================================
//
//	�{�v���O�����́A�p�X���[�h�ɂ��Key Wrap�����{����ׂ̃N���X�ł��B
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.11. 9	����
//======================================================================
/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class PWRI_KEK :
	public Encryption
{
public:
	static	unsigned	int		oid[];

			Encryption*				EncryptionAlgorithm;

	//�A���S���Y��
	static	DES_CBC					ke_DES_CBC;
	static	DES_EDE3_CBC			ke_TDES_CBC;
	static	AES_CBC128				ke_AES_CBC128;		//SIMD���g���֌W�ŁA
	static	AES_CBC192				ke_AES_CBC192;		//static�ɒu���K�v����B
	static	AES_CBC256				ke_AES_CBC256;		//(__declspec(align(16)))

	//Wrap�p
	string	strKey;
	string	strEncrptedKey;

//--------------
//�֐�
					PWRI_KEK(const char _strName[]="PWRI-KEK");
					~PWRI_KEK(void);

			void	Set_PWRI_KEK(unsigned int mode, __m128i IV);
		Encryption*	PWRI_KEK::Get_Encryption(unsigned int mode, __m128i IV);

			void	Set_Key(void *key);							//�Í��� �ݒ�
			void	Clear_Key();								//��Zero��
//			void	init(){};									//������

			//Key Wrap�p
			int		KeyWrap(void *KEK,unsigned int szKEK);	//
			int		KeyUnWrap(void *data,unsigned int szData);	//
			void*	GetKey(){return((void *)strKey.c_str());};
			void*	GetEncrptedKey(){return((void *)strEncrptedKey.c_str());};
};