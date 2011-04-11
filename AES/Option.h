
#pragma once

/****************************************************************/
/*																*/
/*			クラス定義											*/
/*																*/
/****************************************************************/
class OPSW {
public:
				int			iMode;			//暗号利用モード
				char		cDecipher;		//復号
	unsigned	char		fHelp;			//ヘルプを指定したか？

				string		strBINname;		//指定した入力ファイル名
				string		strAESname;		//指定した暗号ファイル名
				string		strKEYname;		//指定した 鍵 ファイル名
				string		strKeyWord;		//暗号鍵を文字列で指定。

		OPSW();								//初期化のみ
		OPSW(int argc, _TCHAR* argv[]);		//引数内容から、クラスを初期化＆ファイルオープン
		~OPSW();							//ファイルクローズ
void	opError(const char *stErrMsg);		//オプションエラー
void	print_help();						//ヘルプ
};
