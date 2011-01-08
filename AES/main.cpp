// AES.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"

//==============================================================
//			16進数 数値表示
//--------------------------------------------------------------
//	●引数
//			int		n		表示Byte数
//			void	*Data	表示する配列[Byte単位]
//	●返値
//			無し
//==============================================================
void	dataPrint(int n, void *Data){

	unsigned char* cData = (unsigned char*)Data;
	int	i=0;
	while(i<n){
		if(((i & 0x0F)==0x00) && (i != 0)){
			printf("\n		 ");
		}
		printf("%02x ",cData[i]);
		i++;
	}
	printf("\n");
}
//==============================================================
//			main routine
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
int __cdecl _tmain(int argc, _TCHAR* argv[])
{

	//Test1	AES-128
	static	const	unsigned	char	test1[16]={	0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
													0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34};
	static	const	unsigned	char	Key1[16]={	0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
													0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c};


	//Test2	AES-192
	static	const	unsigned	char	Key2[24]={	0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
													0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c};


	//Test3	AES-256	
	static	const	unsigned	char	Key3[32]={	0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
													0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c};


	//Test4
	static	const	unsigned	char	test4[16]={	0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
													0x88,0x99,0xaa,0xbb, 0xcc,0xdd,0xee,0xff};
	static	const	unsigned	char	Key4[32]={	0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
													0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
													0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
													0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f};

	__declspec(align(16))	unsigned	char	strCipher[16];

	unsigned	__int64 cycles;		//計測用



	//様々な鍵で、暗号のクラスを作る。
/*
	AES	cAES1(4,Key1);
//	AES	cAES2(6,Key2);
//	AES	cAES3(8,Key3);
	AES	cAES4(4,Key4);
	AES	cAES5(6,Key4);
*/
	AES	cAES6(8,Key4);

/*
	printf("--- test 1 ---\n");
	printf("chiper-key	:");
	dataPrint(16, (char *)Key1);

	printf("plain-text	:");
	dataPrint(16, (char *)test1);
	cAES1.Cipher_One((void *)test1,(void *)strCipher);

	printf("chiper-text	:");
	dataPrint(16, (char *)strCipher);
	cAES1.InvCipher_One((void *)strCipher,(void *)strCipher);

	printf("dechiper-text	:");
	dataPrint(16, (char *)strCipher);





	printf("--- test 4 (AEC 128bit) ---\n");
	printf("chiper-key	:");
	dataPrint(16, (char *)Key4);

	printf("plain-text	:");
	dataPrint(16, (char *)test4);
	cAES4.Cipher_One((void *)test4,(void *)strCipher);

	printf("chiper-text	:");
	dataPrint(16, (char *)strCipher);
	cAES4.InvCipher_One((void *)strCipher,(void *)strCipher);

	printf("dechiper-text	:");
	dataPrint(16, (char *)strCipher);





	printf("--- test 5 (AEC 192bit) ---\n");
	printf("chiper-key	:");
	dataPrint(24, (char *)Key4);

	printf("plain-text	:");
	dataPrint(16, (char *)test4);
	cAES5.Cipher_One((void *)test4,(void *)strCipher);

	printf("chiper-text	:");
	dataPrint(16, (char *)strCipher);
	cAES5.InvCipher_One((void *)strCipher,(void *)strCipher);

	printf("dechiper-text	:");
	dataPrint(16, (char *)strCipher);


*/


	printf("--- test 6 (AEC 256bit) ---\n");
	printf("chiper-key	:");
	dataPrint(32, (char *)Key4);

	printf("plain-text	:");
	dataPrint(16, (char *)test4);
	memcpy(strCipher, test4, 16);

	__asm {
		cpuid
		rdtsc

		mov dword ptr cycles[0], eax // (1)
		mov dword ptr cycles[4], edx
	}

	int	i=0;
	do{
		cAES6.Cipher_One((void *)strCipher,(void *)strCipher);
		i++;
	} while(i<500000);	//16*500,000 = 8 [MByte]の暗号化を想定

	__asm {
		cpuid
		rdtsc

		sub eax, dword ptr cycles[0]  // (2)
		sub edx, dword ptr cycles[4]

		mov dword ptr cycles[0], eax // (3)
		mov dword ptr cycles[4], edx
	}
	printf("暗号：クロックサイクル数 : %u [cycles]\n", cycles );
	//Sbox	Table式	＝	1,876,613,999
	//mulとSBox合体	＝	1,640,267,499
	//アセンブリ言語＝	1,297,764,260

	printf("chiper-text	:");
	dataPrint(16, (char *)strCipher);

	__asm {
		cpuid
		rdtsc

		mov dword ptr cycles[0], eax // (1)
		mov dword ptr cycles[4], edx
	}

	i=0;
	do{
		cAES6.InvCipher_One((void *)strCipher,(void *)strCipher);
		i++;
	} while(i<500000);	//16*500,000 = 8 [MByte]の暗号化を想定

	__asm {
		cpuid
		rdtsc

		sub eax, dword ptr cycles[0]  // (2)
		sub edx, dword ptr cycles[4]

		mov dword ptr cycles[0], eax // (3)
		mov dword ptr cycles[4], edx
	}
	printf("復号：クロックサイクル数 : %u [cycles]\n", cycles );
	//Sbox	Table式	＝	1,876,613,999
	//mul	Table式	＝	1,640,267,499

	printf("dechiper-text	:");
	dataPrint(16, (char *)strCipher);



/*
	delete	&cAES1;
//	delete	&cAES2;
//	delete	&cAES3;
	delete	&cAES4;
	delete	&cAES5;
*/
	delete	&cAES6;

	return 0;
}


