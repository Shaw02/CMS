// AES.cpp : コンソール アプリケーションのエントリ ポイントを定義します。
//

#include "stdafx.h"

/****************************************************************/
/*			定数定義											*/
/****************************************************************/
//暗号処理用バッファ
//#define	Encrypt_Buff	(2048/AES_BlockSize)		//128*16 = 2048
#define	Encrypt_Buff		2048

/****************************************************************/
/*			グローバス変数（クラス）							*/
/****************************************************************/
		OPSW*			cOpsw;			//オプションスイッチ

		//疑似乱数モジュール
		MT_SHA*			cRandom;		//Mersenne Twister with SHA-256

/****************************************************************/
/*			関数												*/
/****************************************************************/
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
//			無し
//	●返値
//			無し
//==============================================================
void	encrypt()
{
	//PKCS#7 の構造定義
	static	const	unsigned	int		oid_PKCS7_1[]	= {1,2,840,113549,1,7,1};
	static	ObjectIdentifier			contentType	= ObjectIdentifier((unsigned int*)oid_PKCS7_1, sizeof(oid_PKCS7_1)/sizeof(unsigned int));

	//変数
	static	FileInput			f_IN	= FileInput(cOpsw->strBINname.c_str());				//ファイル入力用

	union{
		PKCS7_3_Output*	t3;
		PKCS7_6_Output*	t6;
	} f_OUT;

	union{
		PKCS8_Input*	i;
		PKCS8_Output*	o;
	} f_KEY;

	//==========================
	//処理開始
	cout	<<	"Now enciphering..."	<<	endl;

	//------------------
	//暗号化＆暗号ファイルの作成
	switch(cOpsw->iType){
		//------------------
		//Enveloped Data Type
		case(3):
			// 暗号ファイル・オブジェクトの作成
			f_OUT.t3 = new PKCS7_3_Output(cOpsw->strAESname.c_str());
			// (1) 暗号モジュール ＆ セッション鍵（乱数）の準備
			f_OUT.t3->MakeEncryption(cOpsw->iMode);
			// (2) 受信者情報のセット（現状は、鍵導出（パスワード）のみ対応）
			f_OUT.t3->AddRecipient(&cOpsw->strKeyWord, cOpsw->iCount, cOpsw->iMode);
			// (3) 暗号化（ファイル出力込み）
			f_OUT.t3->encrypt(&f_IN, &contentType);
			// 暗号ファイル・オブジェクトの開放
			delete f_OUT.t3;
			break;

		//------------------
		//Encrypted Data Type
		case(6):
			// 暗号ファイル・オブジェクトの作成
			f_OUT.t6 = new PKCS7_6_Output(cOpsw->strAESname.c_str());
			if(cOpsw->iMode == -1){
					//----------
					//暗号鍵ファイルで、使用する暗号モジュール＆暗号鍵を設定する
					f_KEY.i = new PKCS8_Input(cOpsw->strKEYname.c_str());
					f_OUT.t6->Set_Encryption(f_KEY.i);
					delete f_KEY.i;
			} else {
				if(cOpsw->strKeyWord.empty()==true){
					//----------
					//乱数を暗号鍵にして、鍵ファイルに保存する。
					f_KEY.o = new PKCS8_Output(cOpsw->strKEYname.c_str());
					f_OUT.t6->Set_Encryption(f_KEY.o, cOpsw->iMode);
					delete f_KEY.o;
				} else {
					//----------
					//パスワードのSHA-256ハッシュ値を、暗号鍵を生成する。
					f_OUT.t6->Set_Encryption(&cOpsw->strKeyWord, cOpsw->iMode);
				}
			}
			// 暗号化（ファイル出力込み）
			f_OUT.t6->encrypt(&f_IN, &contentType);
			// 暗号ファイル・オブジェクトの開放
			delete f_OUT.t6;
			break;
		//------------------
		//その他
		default:
			errPrint("","undefined type.");
			break;
	}

	//------------------
	//終了
	delete	f_IN;

}
//==============================================================
//			復号処理ルーチン
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	decrypt()
{
	//変数
//	unsigned	int	iType	= 6;		//PKCS#7のタイプ

	static	FileOutput			f_OUT	= FileOutput(cOpsw->strBINname.c_str());		//ファイル出力用

	union{
		PKCS7_3_Input*	t3;
		PKCS7_6_Input*	t6;
	} f_IN;

	PKCS8_Input*	f_KEY;

	//==========================
	//処理開始
	cout	<<	"Now deciphering..."	<<	endl;

	//------------------
	//タイプに応じて復号

	//■ to do	PKCS#7かどうか ＆ タイプのチェック

	switch(cOpsw->iType){
		//------------------
		//Enveloped Data Type
		case(3):
			//暗号ファイルの読み込み ＆ ASN.1構造分析
			f_IN.t3	= new PKCS7_3_Input(cOpsw->strAESname.c_str());
			f_IN.t3->Get_EnvelopedData();
			// 受信者情報の照合
			f_IN.t3->Receipt(&cOpsw->strKeyWord);
			// 暗号化（ファイル出力込み）
			f_IN.t3->decrypt(&f_OUT);
			// 暗号ファイル・オブジェクトの開放
			delete f_IN.t3;
			break;
		//------------------
		//Encrypted Data Type
		case(6):
			//暗号ファイルの読み込み ＆ ASN.1構造分析
			f_IN.t6	= new PKCS7_6_Input(cOpsw->strAESname.c_str());
			f_IN.t6->Get_EncryptedData();
			if(cOpsw->strKeyWord.empty()==true){
				//----------
				//暗号鍵ファイルで、暗号鍵を設定する
				f_KEY = new PKCS8_Input(cOpsw->strKEYname.c_str());
				f_IN.t6->Set_Encryption(f_KEY);
				delete f_KEY;
			} else {
				//----------
				//パスワードのSHA-256ハッシュ値を、暗号鍵を生成する。
				f_IN.t6->Set_Encryption(&cOpsw->strKeyWord);
			}
			// 暗号化（ファイル出力込み）
			f_IN.t6->decrypt(&f_OUT);
			// 暗号ファイル・オブジェクトの開放
			delete f_IN.t6;
			break;
		//------------------
		//その他
		default:
			errPrint("","undefined type.");
			break;
	}

	//------------------
	//終了
	delete	f_OUT;

}
//==============================================================
//			main routine
//--------------------------------------------------------------
//	●引数
//		int			argc		コマンドライン　オプション数
//		_TCHAR*		argv[]		コマンドライン　文字列
//	●返値
//			無し
//==============================================================
int __cdecl _tmain(int argc, _TCHAR* argv[])
{

	unsigned	__int64	cycles = ReadTSC();		//プログラム起動時のクロック数

	//乱数の種用
	union {
		unsigned	int		i[4];
		unsigned	__int64	i64[2];
	} __declspec(align(16)) randSeed;

	//----------------------------------------------------

	//------------------
	//乱数作成
	time((time_t*)&randSeed.i64[0]);	//1970年からの、経過秒数
	randSeed.i64[1] = cycles;			//電源onからの、クロック数
	cRandom	= new MT_SHA((unsigned long *)randSeed.i, sizeof(randSeed)/sizeof(int));		//MT乱数処理

	//------------------
	//オプション処理
	cOpsw	= new OPSW(argc, argv);

	//------------------
	//処理開始
	if(cOpsw->cDecipher == 0){
		encrypt();		//暗号
	} else {
		decrypt();		//復号	
	}

	delete	cOpsw;
	delete	cRandom;

	cout	<<	"Success.\n"
				"Process cycles = "	<<	ReadTSC() - cycles	<<	endl;

	return 0;
}
