#include "stdafx.h"
#include "AES.h"

//==============================================================
//			�R���X�g���N�^
//--------------------------------------------------------------
//	������
//			char					cNK		= 4	: 128bit AES
//											= 6	: 192bit AES
//											= 8	: 256bit AES
//			const	unsigned char	Key[]		: Cipher Key
//	���Ԓl
//			����
//==============================================================
AES::AES()
{
}
//==============================================================
//			�R���X�g���N�^
//--------------------------------------------------------------
//	������
//			char					cNK		= 4	: 128bit AES
//											= 6	: 192bit AES
//											= 8	: 256bit AES
//			const	unsigned char	Key[]		: Cipher Key
//	���Ԓl
//			����
//==============================================================
AES::AES(char cNk,unsigned char Key[])
{
	KeyExpansion(cNk, Key);
}
//==============================================================
//			�f�X�g���N�^
//--------------------------------------------------------------
//	������
//			����
//	���Ԓl
//			����
//==============================================================
AES::~AES(void)
{
}
//==============================================================
//			fips-197	4.2		Multiplication
//--------------------------------------------------------------
//	������
//			*in[16]		Plain-text 
//			*out[16]	Cipher-text
//	���Ԓl
//			out[16]		Cipher-text
//==============================================================
__m128i	AES::mul(__m128i data, unsigned char n)
{
	static	const	_mm_i16	_FF00 = {0xFF00,0xFF00,0xFF00,0xFF00, 0xFF00,0xFF00,0xFF00,0xFF00};
	static	const	_mm_i16	_00FF = {0x00FF,0x00FF,0x00FF,0x00FF, 0x00FF,0x00FF,0x00FF,0x00FF};
	static	const	_mm_i16	_011B = {0x011B,0x011B,0x011B,0x011B, 0x011B,0x011B,0x011B,0x011B};

	__m128i	data1	=	_mm_srli_epi16(	_mm_and_si128(data, _FF00.m128i), 8);
	__m128i	data2	=					_mm_and_si128(data, _00FF.m128i);

	__m128i	result1	=	_mm_setzero_si128();
	__m128i	result2	=	_mm_setzero_si128();

	unsigned	char	i = 0x08;

	do{
		result1	= _mm_slli_epi16(result1, 1);
		result2	= _mm_slli_epi16(result2, 1);

		result1	= _mm_xor_si128(result1, _mm_and_si128(_mm_cmpgt_epi16(result1, _00FF.m128i), _011B.m128i));
		result2	= _mm_xor_si128(result2, _mm_and_si128(_mm_cmpgt_epi16(result2, _00FF.m128i), _011B.m128i));

		if(i & n){
			result1 = _mm_xor_si128(result1, data1);
			result2 = _mm_xor_si128(result2, data2);
		}
		i >>= 1;
	} while (i>0);

	return(_mm_or_si128(_mm_slli_epi16(result1, 8), result2));
}
/*
*/
//==============================================================
//			fips-197	5.2		Key Expansion
//--------------------------------------------------------------
//	������
//			char				cNK		= 4(0100)	: 128bit AES
//										= 6(0110)	: 192bit AES
//										= 8(1000)	: 256bit AES
//			const unsigned char	Key[]				: Cipher Key
//	���Ԓl
//			����
//==============================================================
void	AES::KeyExpansion(char cNk, unsigned char *key)
{
	//The round constant word array.
	static	const	unsigned	int	Rcon[10]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

	unsigned	int	i;
				int	iR;
				int	iRm;
				int	temp;

	Nk	= cNk;
	Nr	= Nk + 6;

	//�����������R�s�[
	i	= 0;
	do{
		_mm_storel_epi64((__m128i*)&w[i], _mm_loadl_epi64((__m128i*)&key[i*4]));
		i++;
		i++;
	} while (i < Nk);

	i		= Nk;
	temp	= w[i-1];
	do{
		iR	= i/Nk;
		iRm	= i%Nk;		//����Z���߂��Q�f���ܑ͖̖̂����B

		if(iRm==0){
			temp = SubWord(RotWord(temp)) ^ Rcon[(iR)-1];
		} else if((Nk > 6) && ( (i%Nk) == 4)){
			temp = SubWord(temp);
		}
		temp	^= w[i-Nk];
		w[i]	 = temp;

		i++;

	} while (i < Nb * (Nr+1));
}
//==============================================================
//			fips-197	5.2		RotWord()
//--------------------------------------------------------------
//	������
//			unsigned int data	4Byte�̐��l
//	���Ԓl
//			unsigned int		ror data,8 �̌���
//==============================================================
unsigned	int	AES::RotWord(unsigned int data)
{
	return( (data>>8) | (data<<24) );		//�܂�	ror data,8
}
//==============================================================
//			fips-197	5.2		Sbox()	(4Byte������)
//--------------------------------------------------------------
//	������
//			unsigned int	data	4Byte�̐��l
//	���Ԓl
//			unsigned int			SBox�K�p��
//==============================================================
unsigned	int	AES::SubWord(unsigned int data)
{
//	fips-197	Figure 7
static	const	unsigned	char	Sbox[256]={
		0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
		0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
		0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
		0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
		0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
		0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
		0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
		0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
		0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
		0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
		0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
		0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
		0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
		0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
		0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
		0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
	};

	//�e�[�u���ϊ��Ɋւ���SIMD���߂͖����H
	unsigned	char	a0	= Sbox[(data    ) & 0xFF];
	unsigned	char	a1	= Sbox[(data>>8 ) & 0xFF];
	unsigned	char	a2	= Sbox[(data>>16) & 0xFF];
	unsigned	char	a3	= Sbox[(data>>24)];

	return(a0 | a1<<8 | a2<<16 | a3<<24);
}
//==============================================================
//			fips-197	5.2		Sbox()	(4Byte������)
//--------------------------------------------------------------
//	������
//			unsigned int	data	4Byte�̐��l
//	���Ԓl
//			unsigned int			SBox�K�p��
//==============================================================
unsigned	int	AES::SubWord2(unsigned int data)
{
//	fips-197	Figure 7
static	const	unsigned	char	Sbox2[256]={
		0xc6,0xf8,0xee,0xf6,0xff,0xd6,0xde,0x91,0x60,0x02,0xce,0x56,0xe7,0xb5,0x4d,0xec,
		0x8f,0x1f,0x89,0xfa,0xef,0xb2,0x8e,0xfb,0x41,0xb3,0x5f,0x45,0x23,0x53,0xe4,0x9b,
		0x75,0xe1,0x3d,0x4c,0x6c,0x7e,0xf5,0x83,0x68,0x51,0xd1,0xf9,0xe2,0xab,0x62,0x2a,
		0x08,0x95,0x46,0x9d,0x30,0x37,0x0a,0x2f,0x0e,0x24,0x1b,0xdf,0xcd,0x4e,0x7f,0xea,
		0x12,0x1d,0x58,0x34,0x36,0xdc,0xb4,0x5b,0xa4,0x76,0xb7,0x7d,0x52,0xdd,0x5e,0x13,
		0xa6,0xb9,0x00,0xc1,0x40,0xe3,0x79,0xb6,0xd4,0x8d,0x67,0x72,0x94,0x98,0xb0,0x85,
		0xbb,0xc5,0x4f,0xed,0x86,0x9a,0x66,0x11,0x8a,0xe9,0x04,0xfe,0xa0,0x78,0x25,0x4b,
		0xa2,0x5d,0x80,0x05,0x3f,0x21,0x70,0xf1,0x63,0x77,0xaf,0x42,0x20,0xe5,0xfd,0xbf,
		0x81,0x18,0x26,0xc3,0xbe,0x35,0x88,0x2e,0x93,0x55,0xfc,0x7a,0xc8,0xba,0x32,0xe6,
		0xc0,0x19,0x9e,0xa3,0x44,0x54,0x3b,0x0b,0x8c,0xc7,0x6b,0x28,0xa7,0xbc,0x16,0xad,
		0xdb,0x64,0x74,0x14,0x92,0x0c,0x48,0xb8,0x9f,0xbd,0x43,0xc4,0x39,0x31,0xd3,0xf2,
		0xd5,0x8b,0x6e,0xda,0x01,0xb1,0x9c,0x49,0xd8,0xac,0xf3,0xcf,0xca,0xf4,0x47,0x10,
		0x6f,0xf0,0x4a,0x5c,0x38,0x57,0x73,0x97,0xcb,0xa1,0xe8,0x3e,0x96,0x61,0x0d,0x0f,
		0xe0,0x7c,0x71,0xcc,0x90,0x06,0xf7,0x1c,0xc2,0x6a,0xae,0x69,0x17,0x99,0x3a,0x27,
		0xd9,0xeb,0x2b,0x22,0xd2,0xa9,0x07,0x33,0x2d,0x3c,0x15,0xc9,0x87,0xaa,0x50,0xa5,
		0x03,0x59,0x09,0x1a,0x65,0xd7,0x84,0xd0,0x82,0x29,0x5a,0x1e,0x7b,0xa8,0x6d,0x2c
	};

	//�e�[�u���ϊ��Ɋւ���SIMD���߂͖����H
	unsigned	char	a0	= Sbox2[(data    ) & 0xFF];
	unsigned	char	a1	= Sbox2[(data>>8 ) & 0xFF];
	unsigned	char	a2	= Sbox2[(data>>16) & 0xFF];
	unsigned	char	a3	= Sbox2[(data>>24)];

	return(a0 | a1<<8 | a2<<16 | a3<<24);
}
//==============================================================
//			fips-197	5.2		Sbox()	(4Byte������)
//--------------------------------------------------------------
//	������
//			unsigned int	data	4Byte�̐��l
//	���Ԓl
//			unsigned int			SBox�K�p��
//==============================================================
unsigned	int	AES::SubWord3(unsigned int data)
{
//	fips-197	Figure 7
static	const	unsigned	char	Sbox3[256]={
		0xa5,0x84,0x99,0x8d,0x0d,0xbd,0xb1,0x54,0x50,0x03,0xa9,0x7d,0x19,0x62,0xe6,0x9a,
		0x45,0x9d,0x40,0x87,0x15,0xeb,0xc9,0x0b,0xec,0x67,0xfd,0xea,0xbf,0xf7,0x96,0x5b,
		0xc2,0x1c,0xae,0x6a,0x5a,0x41,0x02,0x4f,0x5c,0xf4,0x34,0x08,0x93,0x73,0x53,0x3f,
		0x0c,0x52,0x65,0x5e,0x28,0xa1,0x0f,0xb5,0x09,0x36,0x9b,0x3d,0x26,0x69,0xcd,0x9f,
		0x1b,0x9e,0x74,0x2e,0x2d,0xb2,0xee,0xfb,0xf6,0x4d,0x61,0xce,0x7b,0x3e,0x71,0x97,
		0xf5,0x68,0x00,0x2c,0x60,0x1f,0xc8,0xed,0xbe,0x46,0xd9,0x4b,0xde,0xd4,0xe8,0x4a,
		0x6b,0x2a,0xe5,0x16,0xc5,0xd7,0x55,0x94,0xcf,0x10,0x06,0x81,0xf0,0x44,0xba,0xe3,
		0xf3,0xfe,0xc0,0x8a,0xad,0xbc,0x48,0x04,0xdf,0xc1,0x75,0x63,0x30,0x1a,0x0e,0x6d,
		0x4c,0x14,0x35,0x2f,0xe1,0xa2,0xcc,0x39,0x57,0xf2,0x82,0x47,0xac,0xe7,0x2b,0x95,
		0xa0,0x98,0xd1,0x7f,0x66,0x7e,0xab,0x83,0xca,0x29,0xd3,0x3c,0x79,0xe2,0x1d,0x76,
		0x3b,0x56,0x4e,0x1e,0xdb,0x0a,0x6c,0xe4,0x5d,0x6e,0xef,0xa6,0xa8,0xa4,0x37,0x8b,
		0x32,0x43,0x59,0xb7,0x8c,0x64,0xd2,0xe0,0xb4,0xfa,0x07,0x25,0xaf,0x8e,0xe9,0x18,
		0xd5,0x88,0x6f,0x72,0x24,0xf1,0xc7,0x51,0x23,0x7c,0x9c,0x21,0xdd,0xdc,0x86,0x85,
		0x90,0x42,0xc4,0xaa,0xd8,0x05,0x01,0x12,0xa3,0x5f,0xf9,0xd0,0x91,0x58,0x27,0xb9,
		0x38,0x13,0xb3,0x33,0xbb,0x70,0x89,0xa7,0xb6,0x22,0x92,0x20,0x49,0xff,0x78,0x7a,
		0x8f,0xf8,0x80,0x17,0xda,0x31,0xc6,0xb8,0xc3,0xb0,0x77,0x11,0xcb,0xfc,0xd6,0x3a
	};

	//�e�[�u���ϊ��Ɋւ���SIMD���߂͖����H
	unsigned	char	a0	= Sbox3[(data    ) & 0xFF];
	unsigned	char	a1	= Sbox3[(data>>8 ) & 0xFF];
	unsigned	char	a2	= Sbox3[(data>>16) & 0xFF];
	unsigned	char	a3	= Sbox3[(data>>24)];

	return(a0 | a1<<8 | a2<<16 | a3<<24);
}
//==============================================================
//			fips-197	5.2		InvSbox()	(4Byte������)
//--------------------------------------------------------------
//	������
//			unsigned int	data	4Byte�̐��l
//	���Ԓl
//			unsigned int			SBox�K�p��
//==============================================================
unsigned	int	AES::InvSubWord(unsigned int data)
{
//	fips-197	Figure 14
static	const	unsigned	char	InvSbox[256]={
		0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
		0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
		0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
		0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
		0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
		0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
		0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
		0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
		0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
		0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
		0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
		0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
		0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
		0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
		0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
		0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
	};

	//�e�[�u���ϊ��Ɋւ���SIMD���߂͖����H
	unsigned	char	a0	= InvSbox[(data    ) & 0xFF];
	unsigned	char	a1	= InvSbox[(data>>8 ) & 0xFF];
	unsigned	char	a2	= InvSbox[(data>>16) & 0xFF];
	unsigned	char	a3	= InvSbox[(data>>24)];

	return(a0 | a1<<8 | a2<<16 | a3<<24);
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			*in[16]		Plain-text 
//			*out[16]	Cipher-text
//	���Ԓl
//			out[16]		Cipher-text
//==============================================================
void	AES::Cipher_One(void *ind, void *outd)
{
//	_mm_storeu_si128((__m128i*)outd, Cipher(_mm_loadu_si128((__m128i*)ind)));

	_mm_store_si128((__m128i*)outd, AES_SSE_Cipher(Nr,w, _mm_load_si128((__m128i*)ind)));
}
//==============================================================
//			fips-197	5.1		Cipher
//--------------------------------------------------------------
//	������
//			__m128i	data		Plain-text 
//	���Ԓl
//			__m128i				Cipher-text
//==============================================================
__m128i	AES::Cipher(__m128i data)
{
	//��Round [0]
	int	i=0;

	data = AddRoundKey(data, i);
	i++;

	//��Round (1) �` (Nr-1)
	do{
		data = AddRoundKey(MixColumns(ShiftRows((data))),i);
		i++;
	} while(i < Nr);

	//��Round (Nr)
	data = AddRoundKey(ShiftRows(SubBytes(data)),i);

	return(data);
}
//==============================================================
//			fips-197	5.1.1		
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::SubBytes(__m128i data)
{
	//�e�[�u���ϊ��́ASIMD���ł��Ȃ��H
	data.m128i_u32[0] = SubWord(data.m128i_u32[0]);
	data.m128i_u32[1] = SubWord(data.m128i_u32[1]);
	data.m128i_u32[2] = SubWord(data.m128i_u32[2]);
	data.m128i_u32[3] = SubWord(data.m128i_u32[3]);

	return(data);
}
//==============================================================
//			fips-197	5.1.1		
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::SubBytes2(__m128i data)
{
	//�e�[�u���ϊ��́ASIMD���ł��Ȃ��H
	data.m128i_u32[0] = SubWord2(data.m128i_u32[0]);
	data.m128i_u32[1] = SubWord2(data.m128i_u32[1]);
	data.m128i_u32[2] = SubWord2(data.m128i_u32[2]);
	data.m128i_u32[3] = SubWord2(data.m128i_u32[3]);

	return(data);
}
//==============================================================
//			fips-197	5.1.1		
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::SubBytes3(__m128i data)
{
	//�e�[�u���ϊ��́ASIMD���ł��Ȃ��H
	data.m128i_u32[0] = SubWord3(data.m128i_u32[0]);
	data.m128i_u32[1] = SubWord3(data.m128i_u32[1]);
	data.m128i_u32[2] = SubWord3(data.m128i_u32[2]);
	data.m128i_u32[3] = SubWord3(data.m128i_u32[3]);

	return(data);
}
//==============================================================
//			fips-197	5.1.2	ShiftRows
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::ShiftRows(__m128i data)
{
	static	const	_mm_i32	_mask0 = {0x000000FF,0x000000FF,0x000000FF,0x000000FF};
	static	const	_mm_i32	_mask1 = {0x0000FF00,0x0000FF00,0x0000FF00,0x0000FF00};
	static	const	_mm_i32	_mask2 = {0x00FF0000,0x00FF0000,0x00FF0000,0x00FF0000};
	static	const	_mm_i32	_mask3 = {0xFF000000,0xFF000000,0xFF000000,0xFF000000};

	__m128i	a0	=	_mm_and_si128(_mask0.m128i, data);								//�c�����̉�]
	__m128i	a1	=	_mm_and_si128(_mask1.m128i, _mm_shuffle_epi32(data, 0x39));	//0011 1001 b
	__m128i	a2	=	_mm_and_si128(_mask2.m128i, _mm_shuffle_epi32(data, 0x4E));	//0100 1110 b
	__m128i	a3	=	_mm_and_si128(_mask3.m128i, _mm_shuffle_epi32(data, 0x93));	//1001 0011 b

	return(_mm_or_si128(_mm_or_si128(a0,a1),_mm_or_si128(a2,a3)));
}
//==============================================================
//			fips-197	5.1.3	MixColumns
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::MixColumns(__m128i data)
{
	__m128i		a0 = SubBytes2(data);
	__m128i		a1 = SubBytes(data);				//	= mul(data, 1);
	__m128i		a2 = a1;							//	= mul(data, 1);
	__m128i		a3 = SubBytes3(data);

//	__m128i		a0 = mul(data, 2);
//	__m128i		a1 = data;							//	= mul(data, 1);
//	__m128i		a2 = a1;							//	= mul(data, 1);
//	__m128i		a3 = mul(data, 3);
																		//	����SSE���߂�ror����������
																		//	�����������Ɓi32bit�E��]�j
	a1	= _mm_or_si128(_mm_srli_epi32(a1,24),_mm_slli_epi32(a1, 8));	//	prord	a1, 24
	a2	= _mm_or_si128(_mm_srli_epi32(a2,16),_mm_slli_epi32(a2,16));	//	prord	a2, 16
	a3	= _mm_or_si128(_mm_srli_epi32(a3, 8),_mm_slli_epi32(a3,24));	//	prord	a3, 8

	return(_mm_xor_si128(_mm_xor_si128(a0,a1),_mm_xor_si128(a2,a3)));
}
//==============================================================
//			fips-197	5.1.4	
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//			int		i			Round
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::AddRoundKey(__m128i data, int i)
{
	return(_mm_xor_si128(data, _mm_load_si128((__m128i*)&w[i*4])));
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			*in[16]		Plain-text 
//			*out[16]	Cipher-text
//	���Ԓl
//			out[16]		Cipher-text
//==============================================================
void	AES::InvCipher_One(void *ind, void *outd)
{
//	_mm_storeu_si128((__m128i*)outd, InvCipher(_mm_loadu_si128((__m128i*)ind)));

	_mm_storeu_si128((__m128i*)outd, AES_SSE_InvCipher(Nr,w,_mm_loadu_si128((__m128i*)ind)));

}
//==============================================================
//			fips-197	5.3		InvCipher
//--------------------------------------------------------------
//	������
//			__m128i	data		Plain-text 
//	���Ԓl
//			__m128i				Cipher-text
//==============================================================
__m128i	AES::InvCipher(__m128i data)
{
	//��Round (Nr)
	int	i=Nr;

	data = InvAddRoundKey(data, i);
	i--;

	//��Round (Nr-1) �` (1)
	do{
		data = InvMixColumns(InvAddRoundKey(InvShiftRows(InvSubBytes(data)),i));
		i--;
	} while(i > 0);

	//��Round (0)
	data = InvAddRoundKey(InvShiftRows(InvSubBytes(data)), i);

	return(data);
}
//==============================================================
//			fips-197	5.3.1	InvShiftRows
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::InvShiftRows(__m128i data)
{
	static	const	_mm_i32	_mask0 = {0x000000FF,0x000000FF,0x000000FF,0x000000FF};
	static	const	_mm_i32	_mask1 = {0x0000FF00,0x0000FF00,0x0000FF00,0x0000FF00};
	static	const	_mm_i32	_mask2 = {0x00FF0000,0x00FF0000,0x00FF0000,0x00FF0000};
	static	const	_mm_i32	_mask3 = {0xFF000000,0xFF000000,0xFF000000,0xFF000000};

	__m128i		a0	= _mm_and_si128(_mask0.m128i, data);							//�c�����̉�]
	__m128i		a1	= _mm_and_si128(_mask3.m128i, _mm_shuffle_epi32(data, 0x39));	//0011 1001 b
	__m128i		a2	= _mm_and_si128(_mask2.m128i, _mm_shuffle_epi32(data, 0x4E));	//0100 1110 b
	__m128i		a3	= _mm_and_si128(_mask1.m128i, _mm_shuffle_epi32(data, 0x93));	//1001 0011 b

	return(_mm_or_si128(_mm_or_si128(a0,a1),_mm_or_si128(a2,a3)));
}
//==============================================================
//			fips-197	5.3.2	InvSubBytes
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::InvSubBytes(__m128i data)
{
	//�e�[�u���ϊ��́ASIMD���ł��Ȃ��H
	data.m128i_u32[0] = InvSubWord(data.m128i_u32[0]);
	data.m128i_u32[1] = InvSubWord(data.m128i_u32[1]);
	data.m128i_u32[2] = InvSubWord(data.m128i_u32[2]);
	data.m128i_u32[3] = InvSubWord(data.m128i_u32[3]);

	return(data);
}
//==============================================================
//			fips-197	5.3.3	InvMixColumns
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::InvMixColumns(__m128i data)
{
	__m128i		a0 = mul(data, 0x0E);
	__m128i		a1 = mul(data, 0x09);
	__m128i		a2 = mul(data, 0x0D);
	__m128i		a3 = mul(data, 0x0B);
																		//	����SSE���߂�ror����������
																		//	�����������Ɓi32bit�E��]�j
	a1	= _mm_or_si128(_mm_srli_epi32(a1,24),_mm_slli_epi32(a1, 8));	//	prord	a1, 24
	a2	= _mm_or_si128(_mm_srli_epi32(a2,16),_mm_slli_epi32(a2,16));	//	prord	a2, 16
	a3	= _mm_or_si128(_mm_srli_epi32(a3, 8),_mm_slli_epi32(a3,24));	//	prord	a3, 8

	return(_mm_xor_si128(_mm_xor_si128(a0,a1),_mm_xor_si128(a2,a3)));
}
//==============================================================
//			fips-197	5.3.4	InvAddRoundKey
//--------------------------------------------------------------
//	������
//			__m128i	data		Input
//			int		i			Round
//	���Ԓl
//			__m128i				Output
//==============================================================
__m128i	AES::InvAddRoundKey(__m128i data, int i)
{
	return(_mm_xor_si128(data, _mm_load_si128((__m128i*)&w[i*4])));
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			__m128i data	�����l
//	���Ԓl
//			����
//==============================================================
void	AES::SetIV(__m128i data)
{
	IV = data;
}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			void *data		����
//	���Ԓl
//			����
//==============================================================
void	AES::CBC_Cipher(void *data)
{
	__m128i	temp = _mm_load_si128((__m128i*)data);

	temp = AES_SSE_Cipher(Nr,w, _mm_xor_si128(temp, IV));
	_mm_store_si128((__m128i*)data, temp);
	IV = temp;

}
//==============================================================
//			fips-197	
//--------------------------------------------------------------
//	������
//			void *data		�Í���
//	���Ԓl
//			����
//==============================================================
void	AES::CBC_InvCipher(void *data)
{
	__m128i	temp	= _mm_load_si128((__m128i*)data);
	__m128i	out		= _mm_xor_si128(AES_SSE_InvCipher(Nr,w,temp), IV);

	IV	= _mm_load_si128((__m128i*)data);

	_mm_store_si128((__m128i*)data, out);
}