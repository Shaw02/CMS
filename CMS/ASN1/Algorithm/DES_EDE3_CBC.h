#pragma once
#include "DES_EDE3.h"

//======================================================================
//					DES-EDE3-CBC	Encoder / Decorder
//----------------------------------------------------------------------
//  Reference:
//	sp800-17	Modes of Operation Validation System(MOVS) : Requirements and Procedures
//	sp800-67	Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher
//======================================================================
//
//	�{�v���O�����́A�R�c�d�r�Í��ɂ�����
//	�Í����p���[�h�b�a�b�̂��߂̊��N���X�ł��B
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
class DES_EDE3_CBC :
	public DES_EDE3
{
public:
	static	unsigned	int		oid[];
	unsigned			__int64	vector;

	OctetString			IV;

//--------------
//�֐�
					DES_EDE3_CBC(const char _strName[]="DES-EDE3-CBC");
					DES_EDE3_CBC(unsigned __int64 IV, const char _strName[]="DES-EDE3-CBC");
					~DES_EDE3_CBC(void);

			void	Set_DES(unsigned __int64 IV);
			void	SetIV(void *data);
			void	initIV();

			void	init(){initIV();};			//������
			void	encrypt(void *data);
			void	decrypt(void *data);
};
