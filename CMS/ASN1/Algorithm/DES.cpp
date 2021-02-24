#include "stdafx.h"
#include "DES.h"

//==============================================================
//			コンストラクタ
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
DES::DES(const char _strName[]):
	Encryption(_strName)
{
	szBlock	= DES_BlockSize;
	szKey	= DES_KeySize;
}
//==============================================================
//			デストラクタ
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
DES::~DES(void)
{
}
//==============================================================
//			Key Zero
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	DES::Clear_Key()
{
	size_t	i=0;

	while (i < DES_Round){
		k[i] = 0;
		i++;
	};
}
//==============================================================
//			Key Set
//--------------------------------------------------------------
//	●引数
//			void	*key	DES Key (8Byte (7bit * 8 = 56bit))
//	●返値
//			無し
//==============================================================
void	DES::KeyExpansion(void *key, unsigned __int64 ptKS[DES_Round])
{
	static	const	unsigned	char	nshift[16]={
		1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

	static	const	unsigned	char	pc1[56]={
		63,55,47,39,31,23,15,
		 7,62,54,46,38,30,22,
		14, 6,61,53,45,37,29,
		21,13, 5,60,52,44,36,
		57,49,41,33,25,17, 9,
		 1,58,50,42,34,26,18,
		10, 2,59,51,43,35,27,
		19,11, 3,28,20,12, 4};

	static	const	unsigned	 char	pc2[48]={
		42,39,45,32,55,51,
		53,28,41,50,35,46,
		33,37,44,52,30,48,
		40,49,29,36,43,54,
		15, 4,25,19, 9, 1,
		26,16, 5,11,23, 8,
		12, 7,17, 0,22, 3,
		10,14, 6,20,27,24};

	unsigned	__int64*	iKey	= (unsigned	__int64*)key;

	unsigned	__int64		CD;
	unsigned	int			C = 0;
	unsigned	int			D = 0;
				size_t		i,j;
	unsigned	char		r;

	//--------------
	//Permuted Chose 1
	i = 0;
	while(i < 28){	//56
		C <<= 1;
		D <<= 1;
		C |= (*iKey >> pc1[ 0+i]) & 0x01;
		D |= (*iKey >> pc1[28+i]) & 0x01;
		i++;
	}

	i = 0;
	while(i < DES_Round){
		//--------------
		//Left rotate
		r	= nshift[i];
		C	= ((C<<r) | (C>>(28-r))) & 0x0FFFFFFF;	
		D	= ((D<<r) | (D>>(28-r))) & 0x0FFFFFFF;	//28bit
		CD	= C;
		CD<<= 28;
		CD |= D;

		//--------------
		//Permuted Chose 2
		j	= 0;
		while(j < 48){
		//	ptKS[i] <<= 1;
			ptKS[i] <<= ((j%6)?1:3);	//6bitを8bit毎に左詰めする。
			ptKS[i] |= (CD >> pc2[j]) & 0x01;
			j++;
		}
		i++;
	}
}
//==============================================================
//			Initial Premutation (IP)
//--------------------------------------------------------------
//	●引数
//		unsigned	__int64	data	Input
//	●返値
//		unsigned	__int64			Output
//==============================================================
unsigned	__int64	DES::IP(unsigned	__int64	data)
{

	unsigned	__int64	temp;

	unsigned	int	l, r;

	unsigned	int	temp_l,temp_r;

	const	unsigned	int	iMaskL =	0x40100401;
	const	unsigned	int	iMaskR =	0x80200802;

	//Byte単位の入れ替え
	temp  = ( data      & 0xFF) << 32;	//最上位
	temp |= ((data>> 8) & 0xFF);
	temp |= ((data>>16) & 0xFF) << 40;
	temp |= ((data>>24) & 0xFF) <<  8;
	temp |= ((data>>32) & 0xFF) << 48;
	temp |= ((data>>40) & 0xFF) << 16;
	temp |= ((data>>48) & 0xFF) << 56;
	temp |= ((data>>56) & 0xFF) << 24;

	//Bit単位の入れ替え
	r			 =  (unsigned int)(temp>>32);
	temp_l		 = (r & iMaskL);
	r			 =  (unsigned int)(temp & 0xFFFFFFFF);
	temp_r		 = (r & iMaskR);

	temp_l		|= (r & iMaskL) << 1;
	r			 = ((unsigned int)(temp>>32) >>      8 );
	l			 = ((unsigned int)(temp>>32) << (32- 8));
	temp_r		|= (r & iMaskR) << 1;
	temp_r		|= (l & iMaskR) >> 7;

	temp_l		|= (r & iMaskL) << 2;
	temp_l		|= (l & iMaskL) >> 6;
	r			 = ((unsigned int)(temp & 0xFFFFFFFF) >>      8 );
	l			 = ((unsigned int)(temp & 0xFFFFFFFF) << (32- 8));
	temp_r		|= (r & iMaskR) << 2;
	temp_r		|= (l & iMaskR) >> 6;

	temp_l		|= (r & iMaskL) << 3;
	temp_l		|= (l & iMaskL) >> 5;
	r			 = ((unsigned int)(temp>>32) >>     16 );
	l			 = ((unsigned int)(temp>>32) << (32-16));
	temp_r		|= (r & iMaskR) << 3;
	temp_r		|= (l & iMaskR) >> 5;

	temp_l		|= (r & iMaskL) << 4;
	temp_l		|= (l & iMaskL) >> 4;
	r			 = ((unsigned int)(temp & 0xFFFFFFFF) >>     16 );
	l			 = ((unsigned int)(temp & 0xFFFFFFFF) << (32-16));
	temp_r		|= (r & iMaskR) << 4;
	temp_r		|= (l & iMaskR) >> 4;

	temp_l		|= (r & iMaskL) << 5;
	temp_l		|= (l & iMaskL) >> 3;
	r			 = ((unsigned int)(temp>>32) >>     24 );
	l			 = ((unsigned int)(temp>>32) << (32-24));
	temp_r		|= (r & iMaskR) << 5;
	temp_r		|= (l & iMaskR) >> 3;

	temp_l		|= (r & iMaskL) << 6;
	temp_l		|= (l & iMaskL) >> 2;
	r			 = ((unsigned int)(temp & 0xFFFFFFFF) >>     24 );
	l			 = ((unsigned int)(temp & 0xFFFFFFFF) << (32-24));
	temp_r		|= (r & iMaskR) << 6;
	temp_r		|= (l & iMaskR) >> 2;

	temp_l		|= (r & iMaskL) << 7;
	temp_l		|= (l & iMaskL) >> 1;
	l			 =  (unsigned int)(temp>>32);
	temp_r		|= (l & iMaskR) >> 1;

	temp	 = temp_l;
	temp	<<=32;
	temp	|= temp_r;

	return(temp);

}
//==============================================================
//			Inverse Initial Premutation (IP-1)
//--------------------------------------------------------------
//	●引数
//		unsigned	__int64	data	Input
//	●返値
//		unsigned	__int64			Output
//==============================================================
unsigned	__int64	DES::invIP(unsigned	__int64	data)
{
	unsigned	__int64	temp;

	unsigned	__int64	temp0;
	unsigned	__int64	temp1;
	unsigned	__int64	temp2;
	unsigned	__int64	temp3;
	unsigned	__int64	temp4;
	unsigned	__int64	temp5;
	unsigned	__int64	temp6;
	unsigned	__int64	temp7;

	const	unsigned	__int64	iMask =	0x8040201008040201;

	//Byte単位の入れ替え（L,Rの反転も含む）
	temp  = ( data      & 0xFF);	//最上位
	temp |= ((data>> 8) & 0xFF) << 16;
	temp |= ((data>>16) & 0xFF) << 32;
	temp |= ((data>>24) & 0xFF) << 48;

	temp |= ((data>>32) & 0xFF) <<  8;
	temp |= ((data>>40) & 0xFF) << 24;
	temp |= ((data>>48) & 0xFF) << 40;
	temp |= ((data>>56) & 0xFF) << 56;

	//Bit単位の入れ替え
	temp0  = ( temp				) & iMask;

	temp1  = ((temp >>      8	) & iMask) << 1;
	temp1 |= ((temp << (64- 8)	) & iMask) >> 7;

	temp2  = ((temp >>     16	) & iMask) << 2;
	temp2 |= ((temp << (64-16)	) & iMask) >> 6;

	temp3  = ((temp >>     24	) & iMask) << 3;
	temp3 |= ((temp << (64-24)	) & iMask) >> 5;

	temp4  = ((temp >>     32	) & iMask) << 4;
	temp4 |= ((temp << (64-32)	) & iMask) >> 4;

	temp5  = ((temp >>     40	) & iMask) << 5;
	temp5 |= ((temp << (64-40)	) & iMask) >> 3;

	temp6  = ((temp >>     48	) & iMask) << 6;
	temp6 |= ((temp << (64-48)	) & iMask) >> 2;

	temp7  = ((temp >>     56	) & iMask) << 7;
	temp7 |= ((temp << (64-56)	) & iMask) >> 1;

	return(temp0 | temp1 | temp2 | temp3 | temp4 | temp5 | temp6 | temp7);

}
//==============================================================
//			Expand function (32bit to 48bit(8bit formatted) )
//--------------------------------------------------------------
//	●引数
//		unsigned int iData		Input
//	●返値
//		unsigned	__int64		Output
//==============================================================
unsigned	__int64	DES::E(unsigned int iData)
{
	unsigned	__int64	result;
	unsigned	char	a,b,c,d,e,f,g,h;

	a =	((iData<< 1) & 0x3E) | (iData>>31);
	b = ((iData>> 3) & 0x3F);
	c = ((iData>> 7) & 0x3F);
	d = ((iData>>11) & 0x3F);
	e = ((iData>>15) & 0x3F);
	f = ((iData>>19) & 0x3F);
	g = ((iData>>23) & 0x3F);
	h = ((iData>>27) & 0x1F) | ((iData & 1)<<5);

	//鍵も含め、6bitのまとまりを、8bit毎にしておいた方が、処理が早い。
	result	  =	(h<<24) | (g<<16) | (f<<8) | (e);
	result	<<=	32;
	result	 |=	(d<<24) | (c<<16) | (b<<8) | (a);

	return(result);
}
//==============================================================
//			Permutation function
//--------------------------------------------------------------
//	●引数
//		unsigned int iData	Input
//	●返値
//		unsigned int		Output
//==============================================================
unsigned	int		DES::P(unsigned	int	iData)
{
	static	const	unsigned	char	p[32]={
		16,25,12,11,
		 3,20, 4,15,
		31,17, 9, 6,
		27,14, 1,22,
		30,24, 8,18,
		 0, 5,29,23,
		13,19, 2,26,
		10,21,28, 7};

	unsigned	int		result	= 0;
				size_t	i		= 0;

	while(i < 32){	//56
		result <<= 1;
		result |= (iData >> p[i]) & 0x01;
		i++;
	}

	return(result);
}
//==============================================================
//			Cipher function
//--------------------------------------------------------------
//	●引数
//		unsigned	int	iData	Input Data
//		unsigned	int	iKey	Round no.
//	●返値
//		unsigned	int			Output Data
//==============================================================
unsigned	int		DES::f(unsigned	int	iData, unsigned __int64 iKey)
{
	static	const	unsigned	char	s[8][64]={
		14, 0, 4,15,13, 7, 1, 4, 2,14,15, 2,11,13, 8, 1,	//S[0]
		 3,10,10, 6, 6,12,12,11, 5, 9, 9, 5, 0, 3, 7, 8,
		 4,15, 1,12,14, 8, 8, 2,13, 4, 6, 9, 2, 1,11, 7,
		15, 5,12,11, 9, 3, 7,14, 3,10,10, 0, 5, 6, 0,13,
		15, 3, 1,13, 8, 4,14, 7, 6,15,11, 2, 3, 8, 4,14,	//S[1]
		 9,12, 7, 0, 2, 1,13,10,12, 6, 0, 9, 5,11,10, 5,
		 0,13,14, 8, 7,10,11, 1,10, 3, 4,15,13, 4, 1, 2,
		 5,11, 8, 6,12, 7, 6,12, 9, 0, 3, 5, 2,14,15, 9,
		10,13, 0, 7, 9, 0,14, 9, 6, 3, 3, 4,15, 6, 5,10,	//S[2]
		 1, 2,13, 8,12, 5, 7,14,11,12, 4,11, 2,15, 8, 1,
		13, 1, 6,10, 4,13, 9, 0, 8, 6,15, 9, 3, 8, 0, 7,
		11, 4, 1,15, 2,14,12, 3, 5,11,10, 5,14, 2, 7,12,
		 7,13,13, 8,14,11, 3, 5, 0, 6, 6,15, 9, 0,10, 3,	//S[3]
		 1, 4, 2, 7, 8, 2, 5,12,11, 1,12,10, 4,14,15, 9,
		10, 3, 6,15, 9, 0, 0, 6,12,10,11, 1, 7,13,13, 8,
		15, 9, 1, 4, 3, 5,14,11, 5,12, 2, 7, 8, 2, 4,14,
		 2,14,12,11, 4, 2, 1,12, 7, 4,10, 7,11,13, 6, 1,	//S[4]
		 8, 5, 5, 0, 3,15,15,10,13, 3, 0, 9,14, 8, 9, 6,
		 4,11, 2, 8, 1,12,11, 7,10, 1,13,14, 7, 2, 8,13,
		15, 6, 9,15,12, 0, 5, 9, 6,10, 3, 4, 0, 5,14, 3,
		12,10, 1,15,10, 4,15, 2, 9, 7, 2,12, 6, 9, 8, 5,	//S[5]
		 0, 6,13, 1, 3,13, 4,14,14, 0, 7,11, 5, 3,11, 8,
		 9, 4,14, 3,15, 2, 5,12, 2, 9, 8, 5,12,15, 3,10,
		 7,11, 0,14, 4, 1,10, 7, 1, 6,13, 0,11, 8, 6,13,
		 4,13,11, 0, 2,11,14, 7,15, 4, 0, 9, 8, 1,13,10,	//S[6]
		 3,14,12, 3, 9, 5, 7,12, 5, 2,10,15, 6, 8, 1, 6,
		 1, 6, 4,11,11,13,13, 8,12, 1, 3, 4, 7,10,14, 7,
		10, 9,15, 5, 6, 0, 8,15, 0,14, 5, 2, 9, 3, 2,12,
		13, 1, 2,15, 8,13, 4, 8, 6,10,15, 3,11, 7, 1, 4,	//S[7]
		10,12, 9, 5, 3, 6,14,11, 5, 0, 0,14,12, 9, 7, 2,
		 7, 2,11, 1, 4,14, 1, 7, 9, 4,12,10,14, 8, 2,13,
		 0,15, 6,12,10, 9,13, 0,15, 3, 3, 5, 5, 6, 8,11};

	unsigned	int			temp	= 0;
				size_t		i		= 0;
	union{
		unsigned	char	c[8];
		unsigned	__int64	l;
	}	exData;

	//--------------
	//Expand bit & Xor Key Schedule
	exData.l = E(iData) ^ iKey;		//k[iKey];

	//--------------
	//S-Box (Lockup table)
	i = 0;
	while(i<8){
		temp <<=	4;
		temp  |=	s[i][exData.c[7-i]];
		i++;
	}

	//--------------
	//Permutation function
	return(P(temp));

}
//==============================================================
//			Encryption
//--------------------------------------------------------------
//	●引数
//		unsigned __int64
//	●返値
//		unsigned __int64
//==============================================================
unsigned __int64	DES::Cipher(unsigned __int64 iData)
{
	union{
		struct{
			unsigned	int	R;	//下位
			unsigned	int	L;	//上位
		}	i;
		unsigned	__int64	l;
	}	Data;

	size_t	i = 0;

	//--------------
	//IP
	Data.l	= IP(iData);

	//--------------
	//Round
	while(i < DES_Round){
		Data.i.L =	Data.i.L ^ f(Data.i.R, k[i]);
		i++;
		Data.i.R =	Data.i.R ^ f(Data.i.L, k[i]);
		i++;
	}

	//--------------
	//IP-1
	return(invIP(Data.l));
	
}
//==============================================================
//			Decryption
//--------------------------------------------------------------
//	●引数
//		unsigned __int64
//	●返値
//		unsigned __int64
//==============================================================
unsigned __int64	DES::InvCipher(unsigned __int64 iData)
{

	union{
		struct{
			unsigned	int	R;
			unsigned	int	L;
		}	i;
		unsigned	__int64	l;
	}	Data;

	size_t	i = DES_Round;

	//--------------
	//IP
	Data.l	= IP(iData);

	//--------------
	//Round
	while(i>0){
		i--;
		Data.i.L =	Data.i.L ^ f(Data.i.R, k[i]);
		i--;
		Data.i.R =	Data.i.R ^ f(Data.i.L, k[i]);
	}

	//--------------
	//IP-1
	return(invIP(Data.l));	
}
//==============================================================
//			Encryption
//--------------------------------------------------------------
//	●引数
//		void*	data	plain text
//	●返値
//		void*	data	chiper text
//==============================================================
void	DES::encrypt_ecb(void *data)
{
	unsigned __int64*	iData = (unsigned __int64*)data;

	*iData = Cipher(*iData);
}
//==============================================================
//			Decryption
//--------------------------------------------------------------
//	●引数
//		void*	data	cipher text
//	●返値
//		void*	data	plain text
//==============================================================
void	DES::decrypt_ecb(void *data)
{
	unsigned __int64*	iData = (unsigned __int64*)data;

	*iData = InvCipher(*iData);
}