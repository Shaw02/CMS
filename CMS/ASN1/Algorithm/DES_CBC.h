#pragma once
#include "DES.h"

//======================================================================
//					DES-CBC	Encoder / Decorder
//----------------------------------------------------------------------
//  Reference:
//	sp800-17	Modes of Operation Validation System(MOVS) : Requirements and Procedures
//	sp800-67	Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher
//======================================================================
//
//	�{�v���O�����́A�c�d�r�Í��ɂ�����
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
class DES_CBC :
	public DES
{
public:
	static	unsigned	int		oid[];
	unsigned			__int64	vector;

	OctetString			IV;

//--------------
//�֐�
					DES_CBC(const char _strName[]="DES-CBC");
					DES_CBC(unsigned __int64 IV, const char _strName[]="DES-CBC");
					~DES_CBC(void);

			void	Set_DES(unsigned __int64 IV);
			void	SetIV(void *data);
			void	initIV();

			void	init(){initIV();};			//������
			void	encrypt(void *data);
			void	decrypt(void *data);
};
