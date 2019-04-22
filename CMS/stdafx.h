// stdafx.h : 標準のシステム インクルード ファイルのインクルード ファイル、または
// 参照回数が多く、かつあまり変更されない、プロジェクト専用のインクルード ファイル
// を記述します。
//

#pragma once

#include "targetver.h"

//#include <stdio.h>
#include <time.h>
#include <tchar.h>
#include <nmmintrin.h>
#include <wmmintrin.h>

#include <iomanip>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>


// TODO: プログラムに必要な追加ヘッダーをここで参照してください。

using namespace std;

#include "option.h"						//オプション処理

//ファイル処理用
#include "FileInput.h"					//
#include "FileOutput.h"					//

//ASN.1	基本クラス
#include "ASN1\ASN1.h"					//ASN.1用 基底クラス
#include "ASN1\Integer.h"				//0x02
#include "ASN1\OctetString.h"			//0x04
#include "ASN1\ObjectIdentifier.h"		//0x06
#include "ASN1\Sequence.h"				//0x10
#include "ASN1\Set.h"					//0x11
#include "ASN1\Context.h"				//

#include "ASN1\BER_Output.h"			//
#include "ASN1\BER_Input.h"				//

//ASN.1	アルゴリズム
#include "ASN1\Algorithm\AlgorithmIdentifier.h"	//RFC 3370	Algorithm for CMS

//暗号関数(Crypt)
#include "ASN1\Algorithm\Encryption.h"			//			Encryption
#include "ASN1\Algorithm\DES.h"					//fips 46	DES
#include "ASN1\Algorithm\DES_CBC.h"				//
#include "ASN1\Algorithm\DES_EDE3.h"			//
#include "ASN1\Algorithm\DES_EDE3_CBC.h"		//
#include "ASN1\Algorithm\AES.h"					//RFC 3565	AES
#include "ASN1\Algorithm\AES_CBC.h"				//
#include "ASN1\Algorithm\AES_CBC128.h"			//
#include "ASN1\Algorithm\AES_CBC192.h"			//
#include "ASN1\Algorithm\AES_CBC256.h"			//
#include "ASN1\Algorithm\PWRI-KEK.h"			//RFC 3211	Password-based Encryption for CMS

//ハッシュ関数(Digest)
#include "ASN1\Algorithm\Digest.h"				//			Digest
#include "ASN1\Algorithm\SHA.h"					//RFC 4634	SHA　　　ハッシュ基底クラス
#include "ASN1\Algorithm\SHA-1.h"				//RFC 3174	SHA-1　　ハッシュ
#include "ASN1\Algorithm\SHA-224.h"				//RFC 3874	SHA-224　ハッシュ
#include "ASN1\Algorithm\SHA-256.h"				//RFC 5754	SHA-256　ハッシュ

//擬似乱数関数(PRF)
#include "ASN1\Algorithm\HMAC.h"				//RFC 2104  HMAC
#include "ASN1\Algorithm\HMAC-SHA-1.h"			//RFC 2898	HMAC-SHA-1
#include "ASN1\Algorithm\HMAC-SHA-224.h"		//RFC 4231	HMAC-SHA-224
#include "ASN1\Algorithm\HMAC-SHA-256.h"		//RFC 4231	HMAC-SHA-256

#include "ASN1\Algorithm\MT.h"					//MT
#include "ASN1\Algorithm\MT_SHA.h"				//MT with SHA

//鍵導出関数(KDF)
#include "ASN1\Algorithm\KeyDerivation.h"
#include "ASN1\Algorithm\PBKDF2.h"				//RFC 2898	PBKDF2

//ASN.1	PKCS#8（暗号鍵構文）
#include "ASN1\PKCS8\PrivateKeyInfo.h"			//
#include "ASN1\PKCS8\PKCS8.h"					//
#include "ASN1\PKCS8\PKCS8_Input.h"				//
#include "ASN1\PKCS8\PKCS8_Output.h"			//

//ASN.1	PKCS#7（標準暗号メッセージ構文）
#include "ASN1\PKCS7\PasswordRecipientinfo.h"	//RFC 3211	Password-based Encryption for CMS
#include "ASN1\PKCS7\RecipientInfos.h"			//
#include "ASN1\PKCS7\EncryptedContentInfo.h"	//
#include "ASN1\PKCS7\EncryptedData.h"			//
#include "ASN1\PKCS7\EnvelopedData.h"			//
#include "ASN1\PKCS7\ContentInfo.h"				//

#include "ASN1\PKCS7\PKCS7.h"					//
#include "ASN1\PKCS7\PKCS7_Input.h"				//
#include "ASN1\PKCS7\PKCS7_3_Input.h"			//
#include "ASN1\PKCS7\PKCS7_6_Input.h"			//

#include "ASN1\PKCS7\PKCS7_Output.h"			//
#include "ASN1\PKCS7\PKCS7_3_Output.h"			//
#include "ASN1\PKCS7\PKCS7_6_Output.h"			//

/****************************************************************/
/*			外部宣言											*/
/****************************************************************/

extern	MT_SHA*	cRandom;

/****************************************************************/
/*			プロトタイプ										*/
/****************************************************************/
extern "C"	void		dataPrint(int n, void *Data);
extern "C"	void		dataPrint32(int n, void *Data);
void		errPrint(const char *strFile, const char *strMSG);
__int64		ReadTSC();
int			ChkSIMD();
