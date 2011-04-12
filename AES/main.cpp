// AES.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"

//暗号処理用バッファ
#define	AES_Buff_Block	(2048/AES_BlockSize)		//128*16 = 2048

//==============================================================
//			16進数 数値表示
//--------------------------------------------------------------
//	●引数
//			int		n		表示Byte数
//			void	*Data	表示する配列[Byte単位]
//	●返値
//			無し
//==============================================================
void	errPrint(const char *strFile, const char *strMSG)
{
	cout	<<	strFile	<<	strMSG	<<	endl;
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
void	dataPrint(int n, void *Data)
{
	unsigned	char*	cData	= (unsigned char*)Data;
				int		i		= 0;

	cout	<<	setfill('0')	<<	hex;
	while(i<n){
		cout	<<	setw(2)	<<	(int)cData[i]	<<	" ";
		i++;
	}
	cout	<<	dec	<<	endl;
}
//==============================================================
//			16進数 数値表示
//--------------------------------------------------------------
//	●引数
//			int		n		表示DWORD数
//			void	*Data	表示する配列[DWORD単位]
//	●返値
//			無し
//==============================================================
void	dataPrint32(int n, void *Data)
{
	unsigned	int*	cData	= (unsigned int*)Data;
				int		i		= 0;

	cout	<<	setfill('0')	<<	hex;
	while(i<n){
		cout	<<	setw(8)	<<	cData[i]	<<	" ";
		i++;
	}
	cout	<<	dec	<<	endl;

}
//==============================================================
//			get process
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			__int64		プロセス時間
//==============================================================
__int64	ReadTSC()
{
	__asm{
		cpuid
		rdtsc
	}
}
//==============================================================
//			暗号処理ルーチン
//--------------------------------------------------------------
//	●引数
//			OPSW* cOpsw	オプションスイッチ
//	●返値
//			無し
//==============================================================
void	encrypt(OPSW* cOpsw)
{
	//PKCS#7 の構造定義
	static	const	unsigned	int		oid_PKCS7_1[]	= {1,2,840,113549,1,7,1};
	ObjectIdentifier*					_contentType	= new ObjectIdentifier((unsigned int*)oid_PKCS7_1, sizeof(oid_PKCS7_1)/sizeof(unsigned int));

	//変数
	unsigned	__int64	cycles = ReadTSC();		//プログラム起動時のクロック数

	unsigned	int		i,n;					//カウント用
	unsigned	int		ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

				int		cAESmode;				//暗号利用モード
	__m128i				IV;						//init vector


//暗号鍵
union {
		unsigned	char	c[32];
					__m128i	xmm[2];
} __declspec(align(16)) Key;					//暗号鍵

//乱数の種
union {
	unsigned	int		i[4];
	unsigned	__int64	i64[2];
} __declspec(align(16)) randSeed;				//乱数の種

union {
	unsigned	char	c[	(AES_BlockSize*AES_Buff_Block)];
				__m128i	xmm[(AES_BlockSize*AES_Buff_Block/sizeof(__m128i))];
} static __declspec(align(16)) cBuff;

		SHA256*				cSHA	= new	SHA256();				//SHAハッシュ
		MT_SHA*				cMT;									//MT乱数
static	AES					cAES;									//AES暗号処理
		FileInput*			f_IN	= new FileInput(cOpsw->strBINname.c_str());				//ファイル入力用
		PKCS7_6_Output*		f_OUT	= new PKCS7_6_Output(cOpsw->strAESname.c_str());		//ファイル出力用

union{
		PKCS8_Input*		i;		//入力
		PKCS8_Output*		o;		//出力	
} f_KEY;

	//==========================
	//処理開始
	cout	<<	"Now enciphering..."	<<	endl;

	//------------------
	//乱数を初期化
	//（ファイル読み込みにかかった時間が、乱数の種）
	randSeed.i64[0] = cycles;
	randSeed.i64[1] = ReadTSC();
	cMT	= new MT_SHA((unsigned long *)randSeed.i, sizeof(randSeed)/sizeof(int), cSHA);		//MT乱数処理

	//------------------
	//乱数から、IV(Init vector)を生成
	IV	= cMT->get__m128i();		//128bitを、初期ベクトルIVにする

	//------------------
	//鍵の準備
	cAESmode = cOpsw->iMode;

	if(cAESmode == -1){
		//鍵ファイル指定？
		f_KEY.i = new PKCS8_Input(cOpsw->strKEYname.c_str());
		f_KEY.i->Get_PrivateKeyInfo();
		cAESmode = cAES.Check_OID(&f_KEY.i->Algorithm);
		cAES.Set_AES(cAESmode, IV);			//暗号利用モード, 初期化ベクタIV を、設定	
		f_KEY.i->Get_PrivateKey(Key.c, cAES.Nk*4);
		f_KEY.i->close();
		delete f_KEY.i;
	} else {
		cAES.Set_AES(cAESmode, IV);			//暗号利用モード, 初期化ベクタIV を、設定
		if(cOpsw->strKeyWord.empty()==true){
			//鍵は乱数より自動生成
			cMT->get256(&Key.c);
			f_KEY.o = new PKCS8_Output(cOpsw->strKEYname.c_str());
			f_KEY.o->Set(&cAES, (char *)Key.c, (cAES.Nk*4));
			f_KEY.o->encodeBER_to_File();
			f_KEY.o->close();
			delete f_KEY.o;
		} else {
			//キーワードがある場合。
			//文字列のハッシュ値を、暗号鍵用の配列変数に入れる。
			cSHA->CalcHash(Key.c, (void *)cOpsw->strKeyWord.c_str(), cOpsw->strKeyWord.length());
		}
	}

	//乱数は、もう使わない。
	delete	cMT;
	delete	cSHA;

	//------------------
	//暗号鍵を設定
	cAES.Set_Key(Key.c);				//暗号鍵を設定
	Key.xmm[0] = _mm_setzero_si128();	//セキュリティー対策
	Key.xmm[1] = _mm_setzero_si128();	//クラスを暗号鍵で初期化したら、暗号鍵を０クリア

	//------------------
	//PKCS#7-6 の構造をファイル出力
	i = f_IN->GetSize();			//平文のファイルサイズ
	f_OUT->Set_EncryptedData(_contentType, &cAES, (i & -16) + 16);
	f_OUT->write_header();

	delete	_contentType;		//ファイルに出力したので、もういらない。

	//------------------
	//変換
	do{
		//高速化の為、ある程度読み込んで、一気に暗号処理をする。
		f_IN->read((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);

		if(i > AES_BlockSize * AES_Buff_Block){
			n = 0;
			while(n < AES_Buff_Block){
				cAES.encrypt(&cBuff.xmm[n]);
				n++;
			}
			f_OUT->write((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);
			i -= AES_BlockSize * AES_Buff_Block;

		} else {
			n = 0;
			while(i >= AES_BlockSize){
				cAES.encrypt(&cBuff.xmm[n]);
				n++;
				i -= AES_BlockSize;
			}

			//Padding処理(PKCS#7)を実施
			if(n >= AES_Buff_Block){
				f_OUT->write((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);			
				n = 0;
				f_IN->read((char *)cBuff.c, AES_BlockSize * 1);
			}
	
			ptPadding	= i;
			cPadData	= AES_BlockSize - i;
			cntPadData	= cPadData;
			do{
				cBuff.c[n * AES_BlockSize + ptPadding] = cPadData;
				ptPadding++;
				cntPadData--;
			} while(cntPadData>0);
			if(i == AES_BlockSize){
				cAES.encrypt(&cBuff.xmm[n]);
				n++;
			}
			cAES.encrypt(&cBuff.xmm[n]);
			n++;
			f_OUT->write((char *)&cBuff.xmm[0], n * AES_BlockSize);
			break;
		}

	} while(1);

	f_IN->close();
	f_OUT->close();

	delete	f_IN;
	delete	f_OUT;
	
}
//==============================================================
//			復号処理ルーチン
//--------------------------------------------------------------
//	●引数
//			OPSW* cOpsw	オプションスイッチ
//	●返値
//			無し
//==============================================================
void	decrypt(OPSW* cOpsw)
{

	unsigned	int		i,n;					//カウント用
	unsigned	int		ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

				int		cAESmode;				//暗号利用モード
	__m128i				IV;						//init vector

//暗号鍵
union {
		unsigned	char	c[32];
					__m128i	xmm[2];
} __declspec(align(16)) Key;					//暗号鍵

//暗号処理用バッファ
union {
	unsigned	char	c[	(AES_BlockSize*AES_Buff_Block)];
				__m128i	xmm[(AES_BlockSize*AES_Buff_Block/sizeof(__m128i))];
} static __declspec(align(16)) cBuff;

		SHA256*	cSHA	= new	SHA256();				//SHAハッシュ
static	AES		cAES;									//AES暗号処理

	PKCS7_6_Input*		f_IN	= new PKCS7_6_Input(cOpsw->strAESname.c_str());		//ファイル入力用
	FileOutput*			f_OUT	= new FileOutput(cOpsw->strBINname.c_str());		//ファイル出力用

union{
	PKCS8_Input*		i;		//入力
	PKCS8_Output*		o;		//出力	
} f_KEY;

	//==========================
	//処理開始
	cout	<<	"Now deciphering..."	<<	endl;

	//------------------
	//暗号ファイルのASN.1構造分析

	//暗号化コンテンツのサイズ取得
	f_IN->Get_EncryptedData();

	//暗号アルゴリズム・パラメータの取得
	cAESmode = cAES.Check_OID(&f_IN->Algorithm);
	if(cAESmode == -1){
		errPrint(cOpsw->strAESname.c_str(),": Unknown encryption algorithm.");
	}
	f_IN->StreamPointerMove_AlgorithmPara();
	if(sizeof(IV) != f_IN->read_TAG_with_Check(BER_Class_General, false, BER_TAG_OCTET_STRING)){
		errPrint(cOpsw->strAESname.c_str(),": Initialize Vector(IV) is not found.");
	};
	f_IN->read((char *)&IV, sizeof(IV));

	cAES.Set_AES(cAESmode, IV);			//暗号利用モード, 初期化ベクタIV を、設定

	//------------------
	//暗号鍵の準備

	//鍵ファイル
	if(cOpsw->strKeyWord.empty()==true){
		f_KEY.i = new PKCS8_Input(cOpsw->strKEYname.c_str());
		f_KEY.i->Get_PrivateKey_with_check(&cAES, Key.c, cAES.Nk*4);
		f_KEY.i->close();
		delete f_KEY.i;
	//文字列のハッシュ値
	} else {
		cSHA->CalcHash(Key.c, (void *)cOpsw->strKeyWord.c_str(), cOpsw->strKeyWord.length());
	}

	//もう使わない。
	delete	cSHA;

	//------------------
	//変換
	f_IN->StreamPointerMove_EncryptedContent();
	cAES.Set_Key(Key.c);				//暗号鍵を設定
	Key.xmm[0] = _mm_setzero_si128();	//セキュリティー対策
	Key.xmm[1] = _mm_setzero_si128();	//クラスを暗号鍵で初期化したら、暗号鍵を０クリア

	i = f_IN->szEncryptedContent;
	do {
		//高速化の為、ある程度読み込んで、一気に暗号処理をする。
		f_IN->read((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);

		if(i > AES_BlockSize * AES_Buff_Block){
			n = 0;
			while(n < AES_Buff_Block){
				cAES.decrypt(&cBuff.xmm[n]);
				n++;
			}
			f_OUT->write((char *)cBuff.c, AES_BlockSize * AES_Buff_Block);
			i -= AES_BlockSize * AES_Buff_Block;

		} else {
			n = 0;
			while(i > 0){
				cAES.decrypt(&cBuff.xmm[n]);
				n++;
				i -= AES_BlockSize;
			}

			//最後のBlockは、Paddingを含む。
			ptPadding	= n * AES_BlockSize - 1;
			cPadData	= cBuff.c[ptPadding];
			cntPadData	= cPadData;
			//Paddingのチェック
			do{
				if(cBuff.c[ptPadding] != cPadData){
					errPrint(cOpsw->strAESname.c_str(),": Decryption error. Key may be different.");
				}
				ptPadding--;
				cntPadData--;
			} while(cntPadData>0);
			//Paddingデータに基づいてファイル出力
			f_OUT->write((char *)cBuff.c, n * AES_BlockSize - cPadData);
			break;
		}
	} while(1);

	//ファイルを閉じる
	f_IN->close();
	f_OUT->close();

	delete	f_IN;
	delete	f_OUT;
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

	unsigned	__int64	cycles = ReadTSC();		//プログラム起動時のクロック数

	OPSW*	cOpsw	= new OPSW(argc, argv);

	//----------------------------------------------------
	//処理開始

	if(cOpsw->cDecipher == 0){
		encrypt(cOpsw);		//暗号
	} else {
		decrypt(cOpsw);		//復号	
	}

	delete	cOpsw;

	cout	<<	"Success.\n"
				"Process cycles = "	<<	ReadTSC() - cycles	<<	endl;

	return 0;
}
