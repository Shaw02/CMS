
#include "stdafx.h"

//==============================================================
//		コンストラクタ（オプション処理）
//--------------------------------------------------------------
//	●引数
//			int			argc		オプション文字列の数
//			_TCHAR*		argv[]		オプション文字列
//	●返値
//			無し
//	●備考
//			オプションにファイル名が指定されない場合は、ヘルプ表示して終了
//==============================================================
OPSW::OPSW(int argc, _TCHAR* argv[]):
	//初期化設定
	fHelp(0),			//ヘルプは、デフォルトは表示しない。
	cDecipher(1),		//復号モード
	iCount(1000),
	iMode(5),			//鍵のDefault = 42
	iType(3)			
	{

	//----------------------------------
	//■Local 変数
	int		iCount;				//whileのカウント用
	int		iResult;

	//Option処理用
	int		iOptionChk;			//オプションチェック用　ポインタ
	char	cOption;			//オプションチェック用　文字
	char	iFlagFilnameExt;	//拡張子あったかのフラグ

	//----------------------------------------------------
	//SIMD命令のチェック
	fSIMD = ChkSIMD();
	switch(fSIMD){
		case(1):
			cout << "Detect SSE2 instruction sets." << endl;
			break;
		case(2):
			cout << "Detect AES-NI instruction sets." << endl;
			break;
		default:
			cout << "SIMD instruction do not found." << endl;
			exit(-1);
			break;
	}

	//----------------------------------
	//■オプション処理
	iCount=1;	//コマンド名は飛ばす
	while(iCount!=argc)
	{
		//--------------
		//オプションスイッチにスラッシュがあるか確認
		if((argv[iCount][0]=='/')||(argv[iCount][0]=='-')){

			//--------------
			//◆Option Switch	（スラッシュがあった場合の処理）
			switch(argv[iCount][1]){
				//--------
				//Help表示
				case 'h' :
				case 'H' :
				case '?' :
					fHelp=1;
					break;
				//--------
				//Decode
				case 'd' :
				case 'D' :
					cDecipher = 1;
					break;
				//--------
				//Decode
				case 'e' :
				case 'E' :
					cDecipher = 0;
					break;
				//--------
				//ファイルの指定
				case 'T' :
					iResult=sscanf_s(argv[iCount],"/T%d",&iType);
					if((iResult==NULL)||(iResult==EOF)){
						opError("/T");
						break;
					};
					break;
				//--------
				//鍵の指定
				case 'M' :
					iResult=sscanf_s(argv[iCount],"/M%d",&iMode);
					if((iResult==NULL)||(iResult==EOF)){
						opError("/M");
						break;
					};
					break;
				//--------
				//パスワードの指定
				case 'w' :
				case 'W' :
					//先に、キーワードが書いてあるかチェック。
					if(argv[iCount][2]==0){
						opError("/W None pass-word.");
						break;
					};
					//既に指定されている？
					if(strKeyWord.empty()){
						iOptionChk=0;
						while((cOption=argv[iCount][iOptionChk+2])!=0)
						{
							strKeyWord+=cOption;
							iOptionChk++;
						};
					} else {
						opError("/W Too many pass word.");
						break;
					};
					break;
				//--------
				//ファイルの指定
				case 'f' :
				case 'F' :
					//先に、ファイル名が書いてあるかチェック。
					if(argv[iCount][3]==0){
						opError("/F None file-name.");
						break;
					};
					switch(argv[iCount][2]){
						//--------
						//暗号文ファイルの指定
						case 'c' :
							//既に指定されている？
							if(strAESname.empty()){
								iFlagFilnameExt=0;		//拡張子の有無　Reset
								iOptionChk=0;
								while((cOption=argv[iCount][iOptionChk+3])!=0)
								{
									strAESname+=cOption;
									if(cOption=='.'){iFlagFilnameExt=1;};
									iOptionChk++;
								};
								if(iFlagFilnameExt==0){
									strAESname+=".p7";
								};
							} else {
								opError("/F Too many cipher-file-name.");
								break;
							};
							break;
						//--------
						//暗号鍵ファイルの指定
						case 'k' :
							//既に指定されている？
							if(strKEYname.empty()){
								iMode = -1;				//鍵が指定された。
								iFlagFilnameExt=0;		//拡張子の有無　Reset
								iOptionChk=0;
								while((cOption=argv[iCount][iOptionChk+3])!=0)
								{
									strKEYname+=cOption;
									if(cOption=='.'){iFlagFilnameExt=1;};
									iOptionChk++;
								};
								if(iFlagFilnameExt==0){
									strKEYname+=".key";
								};
							} else {
								opError("/F Too many cipher-key.");
								break;
							};
							break;
						default :
							opError("/F");
							break;
					};
					break;
				//--------
				//デフォルト
				default :
					opError("");
					break;
			};

		} else{

			//--------------
			//◆ファイル名	（スラッシュが無かった場合の処理）
			//既に指定されている？
			if(strBINname.empty()){
				iFlagFilnameExt=0;		//拡張子の有無　Reset
				iOptionChk=0;		
				while((cOption=argv[iCount][iOptionChk])!=0)
				{
					strBINname+=cOption;
					if(cOption=='.'){iFlagFilnameExt=1;};
					iOptionChk++;
				};
				if(iFlagFilnameExt==0){
					strBINname+=".";
				};
			} else {
				opError("Too many plain-file-name.");
				break;
			};

		};

		//--------------
		//◆次のオプション
		iCount++;
	};

	//----------------------------------
	//◆オプションで指定された事を処理する。

	//--------------
	//ヘルプ表示
	//ファイル名が書かれなかった場合も、ヘルプを表示する。
	if((fHelp==1)||(strBINname.empty())){print_help();};

	//--------------
	//出力ファイルの指定が無かった場合
	if(strAESname.empty()){
		strAESname = strBINname;
		strAESname+=".p7";
	};

	//--------------
	// 鍵 ファイルの指定が無かった場合
	if(strKEYname.empty()){
		strKEYname = strBINname;
		strKEYname+=".key";
	};

	//--------------
	//

	//	to do	その他のオプションを追加したときは、この辺に追記する。

	//----------
	//Debug用 表示
//	cout << "Plain-Text	= " << strBINname << endl;
//	cout << "Chiper-Text	= " << strAESname << endl;
//	cout << "Chiper-Key	= " << strKEYname << endl;

};
//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//			なし
//	●返値
//			無し
//==============================================================
OPSW::~OPSW(){

};
//==============================================================
//		ヘルプメッセージ
//--------------------------------------------------------------
//	●引数
//			無し
//	●返値
//			無し
//==============================================================
void	OPSW::print_help(){

	cout	<<	"CMS（RFC.5652 ＆ PKCS#7）utility\n"
				"Copyright (C) S.W. (A.Watanabe) 2011-2013\n"
				"\n"
				"CMS [ /options ] [filename]\n"
				"\n"
				"  --- Common option ---\n"
				"  filename		File name of Plain-Text.\n"
				"  /Fc[file(.p7 )]	File name of Cipher-Text. (Default = [filename].p7)\n"
				"  /Fk[file(.key)]	File name of Cipher-Key. (Default = [filename].key)\n"
				"  /W[PW]		Cipher-Key is SHA-256 hash of this PW(Pass Word).\n"
				"  /H			help\n"
				"  /T[n]			Type.\n"
				"			   3 : Enveloped Data(default)\n"
				"			   6 : Encryption Data\n"
				"\n"
				"  --- Decipher option ---\n"
				"  /D			Decipher (Default)\n"
				"\n"
				"  --- Encipher option ---\n"
				"  /E			Encipher\n"
				"  /M[n]			Block cipher modes of operation.\n"
				"			   1 : DES-CBC\n"
				"			   2 : 3-DES-CBC\n"
				"			   3 : AES-CBC 128-bit\n"
				"			   4 : AES-CBC 192-bit\n"
				"			   5 : AES-CBC 256-bit(default)\n" << endl;

	exit(EXIT_SUCCESS);

};
//==============================================================
//		エラー処理	（プロセスも終了する）
//--------------------------------------------------------------
//	●引数
//			char *stErrMsg	エラーメッセージ
//	●返値
//			無し
//==============================================================
void OPSW::opError(const char *stErrMsg){

	cerr << "オプションが不正です。：" << stErrMsg << endl;
	exit(EXIT_FAILURE);

};
