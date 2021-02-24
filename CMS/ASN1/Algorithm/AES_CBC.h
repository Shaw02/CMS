#pragma once
#include "AES.h"

//======================================================================
//					AES-CBC	Encoder / Decorder
//----------------------------------------------------------------------
//  Reference:
//	RFC 3565		Use of the Advanced Encryption Standard (AES) Encryption
//					Algorithm in Cryptographic Message Syntax (CMS)
//======================================================================
//
//	�{�v���O�����́A�`�d�r�Í��ɂ�����
//	�Í����p���[�h�b�a�b�̂��߂̊��N���X�ł��B
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.10. 7	����
//======================================================================
/****************************************************************/
/*			�萔��`											*/
/****************************************************************/


/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class AES_CBC :
	public AES
{
public:
	__m128i				vector;

	OctetString			IV;

//--------------
//�֐�
					AES_CBC(const char _strName[]="AES-CBC");
					~AES_CBC(void);

			void	Set_AES(__m128i _xmm_IV);
			void	SetIV(void *data);
			void	initIV();

			void	init(){initIV();};			//������
			void	encrypt(void *data);
			void	decrypt(void *data);

			//�u���b�N�Í��p
			//�������ׁ̈A��p�̂����B
			void	encipher(void *data,size_t iSize);
			void	decipher(void *data,size_t iSize);
			int		encipher_last(void *data,size_t iSize);
			int		decipher_last(void *data,size_t iSize);

#ifdef	_M_X64
	__m128i	InvCipher_CBC8(__m128i* data, __m128i vector);		//5.3	InvCipher
#else
	__m128i	InvCipher_CBC4(__m128i* data, __m128i vector);		//5.3	InvCipher
#endif
};
