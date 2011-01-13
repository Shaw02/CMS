
#pragma once

/****************************************************************/
/*																*/
/*			クラス定義											*/
/*																*/
/****************************************************************/
class OPSW {
public:
	unsigned	int			iKey;			//鍵
	unsigned	char		cDecode;		//復号
	unsigned	char		fHelp;			//ヘルプを指定したか？
				string		strBINname;		//指定した入力ファイル名
				string		strAESname;		//指定した暗号ファイル名
				string		strKEYname;		//指定した 鍵 ファイル名

		OPSW();								//初期化のみ
		OPSW(int argc, _TCHAR* argv[]);		//引数内容から、クラスを初期化＆ファイルオープン
		~OPSW();							//ファイルクローズ
void	opError(const char *stErrMsg);		//オプションエラー
void	print_help();						//ヘルプ
};
