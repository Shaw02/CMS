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
			void	encipher(void *data,unsigned int iSize);
			void	decipher(void *data,unsigned int iSize);
			int		encipher_last(void *data,unsigned int iSize);
			int		decipher_last(void *data,unsigned int iSize);
};
