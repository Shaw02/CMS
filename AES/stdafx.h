// stdafx.h : 標準のシステム インクルード ファイルのインクルード ファイル、または
// 参照回数が多く、かつあまり変更されない、プロジェクト専用のインクルード ファイル
// を記述します。
//

#pragma once

#include "targetver.h"

//#include <stdio.h>
#include <tchar.h>
#include <nmmintrin.h>

#include <iomanip>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>


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
#include "ASN1\Context.h"				//

#include "ASN1\BER_Output.h"			//
#include "ASN1\BER_Input.h"				//

//ASN.1	アルゴリズム
#include "ASN1\Algorithm\AlgorithmIdentifier.h"
#include "ASN1\Algorithm\AES.h"			//AES暗号
#include "ASN1\Algorithm\SHA.h"			//SHA　　　ハッシュ基底クラス
#include "ASN1\Algorithm\SHA-1.h"		//SHA-1　　ハッシュ
#include "ASN1\Algorithm\SHA-224.h"		//SHA-224　ハッシュ
#include "ASN1\Algorithm\SHA-256.h"		//SHA-256　ハッシュ
#include "ASN1\Algorithm\MT.h"			//MT乱数
#include "ASN1\Algorithm\MT_SHA.h"		//MT乱数 with SHA

//ASN.1	PKCS#7（標準暗号メッセージ構文）
#include "ASN1\PKCS7\EncryptedContentInfo.h"	//
#include "ASN1\PKCS7\EncryptedData.h"			//
#include "ASN1\PKCS7\ContentInfo.h"				//

#include "ASN1\PKCS7\PKCS7_Input.h"			//
#include "ASN1\PKCS7\PKCS7_6_Input.h"		//
#include "ASN1\PKCS7\PKCS7_Output.h"		//
#include "ASN1\PKCS7\PKCS7_6_Output.h"		//

#include "ASN1\PKCS8\PrivateKeyInfo.h"		//
#include "ASN1\PKCS8\PKCS8_Input.h"			//
#include "ASN1\PKCS8\PKCS8_Output.h"		//

void	dataPrint(int n, void *Data);
void	errPrint(const char *strFile, const char *strMSG);