// stdafx.h : 標準のシステム インクルード ファイルのインクルード ファイル、または
// 参照回数が多く、かつあまり変更されない、プロジェクト専用のインクルード ファイル
// を記述します。
//

#pragma once

#include "targetver.h"

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <nmmintrin.h>

#include <string>
#include <iostream>
#include <fstream>

// TODO: プログラムに必要な追加ヘッダーをここで参照してください。

using namespace std;

#include "option.h"			//オプション処理
#include "FileInput.h"		//オプション処理
#include "FileOutput.h"		//オプション処理

#include "AES.h"		//AES暗号
#include "MT.h"			//MT乱数


void	dataPrint(int n, void *Data);
