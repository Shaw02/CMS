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
void	dataPrint(int n, void *Data){

	unsigned char* cData = (unsigned char*)Data;
	int	i=0;

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
void	dataPrint32(int n, void *Data){

	unsigned int* cData = (unsigned int*)Data;
	int	i=0;

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
void	encrypt(OPSW* cOpsw)
{
	//PKCS#7 の構造定義
	static	const	unsigned	int		oid_PKCS7_1[]	= {1,2,840,113549,1,7,1};
	ObjectIdentifier*					_contentType	= new ObjectIdentifier((unsigned int*)oid_PKCS7_1, sizeof(oid_PKCS7_1)/sizeof(unsigned int));

	//変数
	unsigned	__int64	cycles = ReadTSC();		//プログラム起動時のクロック数

	unsigned	int		i;						//カウント用
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

//暗号処理用バッファ（パディング用に16Byte余分に。）
union {
	unsigned	char	c[	(AES_BlockSize*2)];
				__m128i	xmm[(AES_BlockSize*2/sizeof(__m128i))];
} __declspec(align(16)) cBuff;

		SHA256*				cSHA	= new	SHA256();				//SHAハッシュ
		MT_SHA*				cMT;									//MT乱数
static	AES					cAES;									//AES暗号処理
		FileInput*			f_IN	= new FileInput(cOpsw->strBINname.c_str());				//ファイル入力用
		PKCS7_6_Output*		f_OUT	= new PKCS7_6_Output(cOpsw->strAESname.c_str());		//ファイル出力用

union{
		PKCS8_Input*		i;		//入力
		PKCS8_Output*		o;		//出力	
} f_KEY;

	cout	<<	"Now enciphering..."	<<	endl;

	//------------------
	//乱数から、IV(Init vector)を生成
	//（ファイル読み込みにかかった時間が、乱数の種）

	randSeed.i64[0] = cycles;
	randSeed.i64[1] = ReadTSC();
	cMT	=	new MT_SHA((unsigned long *)randSeed.i, sizeof(randSeed)/sizeof(int), cSHA);		//MT乱数処理

	//------------------
	//PKCS#7-6 の構造を作成
	IV = cMT->get__m128i();		//128bitを、初期ベクトルIVにする
	cAESmode = cOpsw->iMode;
//	cAES.Set_AES(cAESmode, IV);			//暗号利用モード, 初期化ベクタIV を、設定

	//------------------
	//鍵の準備

	//鍵ファイル指定？
	if(cAESmode == -1){
		f_KEY.i = new PKCS8_Input(cOpsw->strKEYname.c_str());
		f_KEY.i->Get_PrivateKeyInfo();
		cAESmode = cAES.Check_OID(&f_KEY.i->Algorithm);
		cAES.Set_AES(cAESmode, IV);			//暗号利用モード, 初期化ベクタIV を、設定	
		f_KEY.i->Get_PrivateKey(Key.c, cAES.Nk*4);
		f_KEY.i->close();
		delete f_KEY.i;
	} else {
		cAES.Set_AES(cAESmode, IV);			//暗号利用モード, 初期化ベクタIV を、設定
		//鍵は乱数より自動生成
		if(cOpsw->strKeyWord.empty()==true){
			cMT->get256(&Key.c);
			f_KEY.o = new PKCS8_Output(cOpsw->strKEYname.c_str());
			f_KEY.o->Set(&cAES, (char *)Key.c, (cAES.Nk*4));
			f_KEY.o->encodeBER_to_File();
			f_KEY.o->close();
			delete f_KEY.o;
		//キーワードがある場合。
		} else {
			//文字列のハッシュ値を、暗号鍵用の配列変数に入れる。
			cSHA->CalcHash(Key.c, (void *)cOpsw->strKeyWord.c_str(), cOpsw->strKeyWord.length());
		}
	}

	delete	cMT;				//乱数は、もう使わない。

	//------------------
	//暗号鍵を設定
	cAES.Set_Key(Key.c);				//暗号鍵を設定
	Key.xmm[0] = _mm_setzero_si128();	//セキュリティー対策
	Key.xmm[1] = _mm_setzero_si128();	//クラスを暗号鍵で初期化したら、暗号鍵を０クリア

	//------------------
	//PKCS#7-6 の構造をファイル出力
	i = f_IN->GetSize();		//平文のファイルサイズ
	f_OUT->Set_EncryptedData(_contentType, &cAES, (i & -16) + 16);
	f_OUT->write_header();

	//------------------
	//変換
	do{

		f_IN->read((char *)cBuff.c, AES_BlockSize);

		if(i > AES_BlockSize){
			cAES.encrypt(&cBuff.xmm[0]);
			f_OUT->write((char *)cBuff.c, AES_BlockSize);
			i -= AES_BlockSize;
		} else {
			//Padding処理(PKCS#7)を実施
			ptPadding	= i;
			cPadData	= AES_BlockSize - (i & 0x0F);
			cntPadData	= cPadData;
			do{
				cBuff.c[ptPadding] = cPadData;
				ptPadding++;
				cntPadData--;
			} while(cntPadData>0);

			cAES.encrypt(&cBuff.xmm[0]);
			f_OUT->write((char *)&cBuff.xmm[0], AES_BlockSize);
			if(i == AES_BlockSize){
				//Paddingが次のblockにある場合
				cAES.encrypt(&cBuff.xmm[1]);
				f_OUT->write((char *)&cBuff.xmm[1], AES_BlockSize);
			}
			break;
		}

	} while(1);

	f_IN->close();
	f_OUT->close();

	delete	f_IN;
	delete	f_OUT;
	delete	cSHA;
	
	delete	_contentType;
}
//==============================================================
//			main routine
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	decrypt(OPSW* cOpsw)
{

	unsigned	int		i;						//カウント用
	unsigned	int		ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

				int		cAESmode;				//暗号利用モード
	__m128i				IV;						//init vector

	bool	fStruct;							//ASN.1 構文解析用

//暗号鍵
union {
		unsigned	char	c[32];
					__m128i	xmm[2];
} __declspec(align(16)) Key;					//暗号鍵

//暗号処理用バッファ（パディング用に16Byte余分に。）
union {
	unsigned	char	c[	(AES_BlockSize*2)];
				__m128i	xmm[(AES_BlockSize*2/sizeof(__m128i))];
} __declspec(align(16)) cBuff;

		SHA256*	cSHA	= new	SHA256();				//SHAハッシュ
static	AES		cAES;									//AES暗号処理

	PKCS7_6_Input*		f_IN	= new PKCS7_6_Input(cOpsw->strAESname.c_str());		//ファイル入力用
	FileOutput*			f_OUT	= new FileOutput(cOpsw->strBINname.c_str());		//ファイル出力用

union{
	PKCS8_Input*		i;		//入力
	PKCS8_Output*		o;		//出力	
} f_KEY;

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
	if(sizeof(IV) != f_IN->read_TAG_with_Check(BER_Class_General, BER_TAG_OCTET_STRING, &fStruct)){
		errPrint(cOpsw->strAESname.c_str(),": Initialize Vector(IV) is not found.");
	};
	if(fStruct != false){
		f_IN->error(0);
	}
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


	//------------------
	//変換
	f_IN->StreamPointerMove_EncryptedContent();
	cAES.Set_Key(Key.c);				//暗号鍵を設定
	Key.xmm[0] = _mm_setzero_si128();	//セキュリティー対策
	Key.xmm[1] = _mm_setzero_si128();	//クラスを暗号鍵で初期化したら、暗号鍵を０クリア

	i = f_IN->szEncryptedContent;
	do {
		f_IN->read((char *)cBuff.c, AES_BlockSize);
		cAES.decrypt(&cBuff.xmm[0]);
		i -= AES_BlockSize;
		if(i >= AES_BlockSize){
			f_OUT->write((char *)cBuff.c, AES_BlockSize);
		} else {
			//最後のBlockは、Paddingを含む。
			ptPadding	= AES_BlockSize - 1;
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
			f_OUT->write((char *)cBuff.c, AES_BlockSize - cPadData);
			break;
		}
	} while(1);

	//ファイルを閉じる
	f_IN->close();
	f_OUT->close();

	delete	f_IN;
	delete	f_OUT;
	delete	cSHA;
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
