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
void	errPrint(const char *strFile, const char *strMSG){

	printf(strFile);
	printf(strMSG);
	exit(EXIT_FAILURE);
}


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
//			get process
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
__int64	ReadTSC()
{
	__asm{
		cpuid
		rdtsc
	}
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

#define	strAES	0x00534541

	__declspec(align(16))	unsigned	char	text[16];	//処理用
union {
	__declspec(align(16))	unsigned	char	c[32];
	__declspec(align(16))	unsigned	int		i[8];
} Key;														//暗号鍵

struct Header{
	unsigned	int		Name;					//ヘッダー
	unsigned	int		iKeySize;				//暗号鍵のサイズ(128,192,256)
	unsigned	int		Null;					//
	unsigned	int		iSize;					//ファイルサイズ
	union{
		unsigned	char	c[16];
		unsigned	int		i[4];
		__m128i				xmm;
	} IV;										//CBCモード 初期値
} __declspec(align(16)) header;					//ヘッダー

union {
	unsigned	__int64	i64[2];
	unsigned	long	i[4];
} randSeed;										//乱数生成用

union {
	unsigned	__int64 i64;
	unsigned	int		i[2];
} cycles;										//サイクル数カウント用

	unsigned	int		i;						//カウント用
	unsigned	int		n;						//カウント用

		OPSW*	cOpsw	= new	OPSW(argc, argv);		//オプションスイッチ処理
		MT*		cMT;									//MT乱数
static	AES		cAES;									//AES暗号処理

	FileInput*			f_IN	= new FileInput();		//ファイル入力用
	FileOutput*			f_OUT	= new FileOutput();		//ファイル出力用
union{
	FileInput*			i;		//入力
	FileOutput*			o;		//出力	
} f_KEY;

	//----------------------------------------------------
	//処理開始
	cycles.i64 = ReadTSC();				//計測用 ＆ 乱数の種
//	header = new Header;

	//----------------------------------------------------
	//■暗号
	if(cOpsw->cDecode == 0){

		//------------------
		//ファイルを開く（ファイル読み込み時間を、乱数生成時間にする）
		f_IN->fileopen(cOpsw->strBINname.c_str());
		f_OUT->fileopen(cOpsw->strAESname.c_str());

		//------------------
		//ヘッダー作成(1)
		header.Name		= strAES;
		header.iSize	= f_IN->GetSize();
		header.iKeySize	= cOpsw->iKey;

		//乱数生成（ファイル読み込みにかかった時間が、乱数の種）
		randSeed.i64[0] = cycles.i64;
		randSeed.i64[1] = ReadTSC();
		cMT	=	new MT(randSeed.i, 4);					//MT乱数処理

		header.IV.i[0] = cMT->genrand_int32();
		header.IV.i[1] = cMT->genrand_int32();
		header.IV.i[2] = cMT->genrand_int32();
		header.IV.i[3] = cMT->genrand_int32();

		//------------------
		//鍵の準備
		//鍵ファイル有り
		if(header.iKeySize == 0){
			f_KEY.i = new FileInput();
			f_KEY.i->fileopen(cOpsw->strKEYname.c_str());
			header.iKeySize = f_KEY.i->GetSize()<<3;	//暗号鍵のサイズをヘッダーにセット
			if((header.iKeySize!=128)&&(header.iKeySize!=192)&&(header.iKeySize!=256)){
				errPrint(cOpsw->strKEYname.c_str(), ": Not chiper-key file.");
			}
			f_KEY.i->read((char *)Key.c, sizeof(Key.c));
			f_KEY.i->close();
			delete f_KEY.i;
		//鍵は自動生成
		} else {
			f_KEY.o = new FileOutput();
			f_KEY.o->fileopen(cOpsw->strKEYname.c_str());
			i =  header.iKeySize>>5;
			do{
				i--;
				Key.i[i] = cMT->genrand_int32();		//乱数で暗号鍵を生成
			} while(i>0);
			f_KEY.o->write((char *)Key.c, header.iKeySize>>3);
			f_KEY.o->close();
			delete f_KEY.o;
		}

		delete	cMT;

		//------------------
		//変換
		cAES.KeyExpansion(header.iKeySize>>5,Key.c);
		cAES.SetIV(header.IV.xmm);
		f_OUT->write((char *)&header, sizeof(Header));
		i = header.iSize;
		while(i>0){
			n = ((i>16)?16:i);
			f_IN->read((char *)text, 16);
			cAES.CBC_Cipher(text);
			f_OUT->write((char *)text, 16);
			i -= n;
		}

	//----------------------------------------------------
	//■復号	
	} else {

		//------------------
		//ファイルを開く
		f_IN->fileopen(cOpsw->strAESname.c_str());
		f_OUT->fileopen(cOpsw->strBINname.c_str());

		//------------------
		//ヘッダー読み込み ＆ チェック
		f_IN->read((char *)&header, sizeof(Header));
		if(header.Name != strAES){
			errPrint(cOpsw->strAESname.c_str(), ": Not chiper-text file.");
		}

		//------------------
		//暗号鍵の準備
		f_KEY.i = new FileInput();
		f_KEY.i->fileopen(cOpsw->strKEYname.c_str());
		if((f_KEY.i->GetSize()) != header.iKeySize>>3){
			errPrint(cOpsw->strKEYname.c_str(), ": Not chiper-key file.");
		}
		f_KEY.i->read((char *)Key.c, header.iKeySize>>3);
		f_KEY.i->close();
		delete f_KEY.i;

		//------------------
		//変換
		cAES.KeyExpansion(header.iKeySize>>5,Key.c);
		cAES.SetIV(header.IV.xmm);
		i = header.iSize;
		while(i>0){
			n = ((i>16)?16:i);
			f_IN->read((char *)text, 16);
			cAES.CBC_InvCipher(text);
			f_OUT->write((char *)text, n);
			i -= n;
		}

	}

	//ファイルを閉じる
	f_IN->close();
	f_OUT->close();

	delete	f_IN;
	delete	f_OUT;
	delete	cOpsw;

	printf("%u:%u サイクル要しました。\n", ReadTSC() - cycles.i64);

	return 0;
}


