
#include "stdafx.h"

//==============================================================
//		オプション処理
//--------------------------------------------------------------
//	●引数
//			int argc		オプション文字列の数
//			_TCHAR* argv[]	オプション文字列
//	●返値
//			SMF.name[]		変換元のSMFファイル
//			MML.name[]		変換先のMMLファイル
//	●備考
//			オプションにファイル名が指定されない場合は、ヘルプ表示して終了
//==============================================================
OPSW::OPSW(int argc, _TCHAR* argv[]):
	//初期化設定
	fHelp(0),		//ヘルプは、デフォルトは表示しない。
	cDecode(1),		//でバッグ
	iKey(256)		//鍵は指定
	{

	//----------------------------------
	//■Local 変数
	int		iCount;				//whileのカウント用
	int		iResult;

	//Option処理用
	int		iOptionChk;			//オプションチェック用　ポインタ
	char	cOption;			//オプションチェック用　文字
	char	iFlagFilnameExt;	//拡張子あったかのフラグ

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
				case 'D' :
					cDecode = 1;
					break;
				//--------
				//Decode
				case 'E' :
					cDecode = 0;
					break;
				//--------
				//鍵の指定
				case 'K' :
					iResult=sscanf_s(argv[iCount],"/K%d",&iKey);
					if((iResult==NULL)||(iResult==EOF)){
						opError("/K");
						break;
					};
					if((iKey!=0)&&(iKey!=128)&&(iKey!=192)&&(iKey!=256)){
						opError("/K 未対応の鍵長です。");
						break;
					}
					break;
				//--------
				//ファイルの指定
				case 'F' :
					//先に、ファイル名が書いてあるかチェック。
					if(argv[iCount][3]==0){
						opError("/F ファイル名が書いてありません。");
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
									strAESname+=".aes";
								};
							} else {
								opError("/F 暗号文ファイルが2回以上指定されました。");
								break;
							};
							break;
						//--------
						//暗号鍵ファイルの指定
						case 'k' :
							//既に指定されている？
							if(strKEYname.empty()){
								iKey = 0;				//鍵が指定された。
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
								opError("/F 暗号鍵ファイルが2回以上指定されました。");
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
				opError("平文ファイルが2回以上指定されました。");
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
		strAESname+=".aes";
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
//		デストラクト
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
//			なし
//	●返値
//			無し
//==============================================================
void	OPSW::print_help(){

	cout	<<	"AES cipher decorder and encoder.\n"
				"Copyright (C) S.W. (A.Watanabe) 2011\n"
				"\n"
				"AES [ /options ] [filename]\n"
				"\n"
				"  filename		File name of Plain-Text.\n"
				"  /Fc[file(.aes)]	File name of Cipher-Text. (Default = [filename].aes)\n"
				"  /Fk[file(.key)]	File name of Cipher-Key. (Default = [filename].key)\n"
				"  /D			Decode cipher (Default)\n"
				"  /E			Encode cipher \n"
				"  /Kn			Auto-make cipher key by rumdom.\n"
				"			 128 : AES-128\n"
				"			 192 : AES-192\n"
				"			 256 : AES-256 (default)\n"
				"  /H			help"	<<	endl;

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
