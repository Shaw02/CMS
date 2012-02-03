#pragma once
#include "Encryption.h"

//======================================================================
//	FIPS Pub 46-3	DATA ENCRYPTION STANDARD (DES)
//----------------------------------------------------------------------
//  Reference:
//	sp800-17	Modes of Operation Validation System(MOVS) : Requirements and Procedures
//	sp800-67	Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher
//======================================================================
//
//	�{�v���O�����́A�c�d�r�Í����������܂��B
//	PBKDF2�֐��̃f�o�b�O�ׂ̈ɍ쐬���܂����B
//	i80x86 32bit�p�iSIMD���ߖ��g�p�j�ɃR�[�f�B���O���Ă��܂��B
//
//	���A�{�N���X��A�\�[�X�R�[�h�̗��p������ۂ́A����񂭂������B
//	���A�{�N���X��A�\�[�X�R�[�h�̗��p�ɂ�蔭�����������Ȃ�
//	���Q�ɂ��܂��Ă͖@�������e����ő���ɂ����ĐӔC�𕉂��܂���̂ŁA
//	�g�p�҂̐ӔC�̌��A�����p������΍K���ł��B
//
//	�g�����́A�b++����̃\�[�X��ǂ�ł��������B
//
//						Copyright (c) A.Watanabe (2011)
//
//----------------------------------------------------------------------
//	Revision
//		2011.11. 9	����
//======================================================================
/****************************************************************/
/*			�萔��`											*/
/****************************************************************/
#define		DES_BlockSize		8
#define		DES_KeySize_b		64
#define		DES_KeySize			DES_KeySize_b/8
#define		DES_Round			16
/****************************************************************/
/*			�v���g�^�C�v�錾									*/
/****************************************************************/
//�A�Z���u������ŏ����ꂽ�֐�	"AES_sse.asm"
/*
extern "C"{
				__m128i	__fastcall	AES_SSE_Cipher(unsigned char cNr,unsigned int *ptrKs, __m128i data);
				__m128i	__fastcall	AES_SSE_InvCipher(unsigned char cNr,unsigned int *ptrKs, __m128i data);}
*/

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class __declspec(align(16)) DES :
	public Encryption
{
//Variable
public:
	enum				useMode{ECB, CBC, OFB, CFB, CTR, CTS}	mode;

	unsigned	__int64	k[DES_Round];

//Function
public:
	DES(const char _strName[]="DES");							//
	~DES(void);													//

			void	Set_Key(void *key){KeyExpansion((unsigned char *)key, k);};		//�Í��� �ݒ�
			void	Clear_Key();								//��Zero��
//			void	init(){};									//������
			void	encrypt_ecb(void *data);
			void	decrypt_ecb(void *data);

//protected:
				void	KeyExpansion(void *key, unsigned __int64 ptKS[DES_Round]);		//�Í��� �ݒ�
	unsigned __int64	Cipher(unsigned __int64 iData);
	unsigned __int64	InvCipher(unsigned __int64 iData);

	unsigned	__int64	IP(unsigned __int64	data);						//Initial Premutation
	unsigned	__int64	invIP(unsigned __int64 data);					//Inverse Initial Premutation
	unsigned	int		f(unsigned	int	iData, unsigned __int64 iKey);	//Cipher function
	unsigned	__int64	E(unsigned int iData);							//Expand function
	unsigned	int		P(unsigned	int	iData);							//Permutation function
};
