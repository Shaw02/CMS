#include "StdAfx.h"
#include "Encryption.h"

//==============================================================
//		コンストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
Encryption::Encryption(const char _strName[]):
	AlgorithmIdentifier(_strName)
{
}
//==============================================================
//		デストラクタ
//--------------------------------------------------------------
//	●引数
//				無し
//	●返値
//				無し
//==============================================================
Encryption::~Encryption(void)
{
	//クラスを解放する前に、鍵スケジュールを０クリアする。
	Clear_Key();
}
//==============================================================
//			平文の入力
//--------------------------------------------------------------
//	●引数
//			void			*data	平文
//			unsigned int	iSize	平文のサイズ
//	●返値
//			無し
//==============================================================
void	Encryption::encipher(void *data,unsigned int iSize)
{
	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	while(n < iSize){
		encrypt(&cData[n]);
		n	+=	szBlock;
	}
}
//==============================================================
//			平文の入力（最終）
//--------------------------------------------------------------
//	●引数
//			void			*data	平文
//			unsigned	int	iSize	平文のサイズ
//	●返値
//						int			Paddingとして追加したサイズ
//==============================================================
int		Encryption::encipher_last(void *data,unsigned int iSize)
{
	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	unsigned	int		ptPadding;
	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//暗号（最終ブロック直前まで）
	while(iSize >= szBlock){
		encrypt(&cData[n]);
		n		+= szBlock;
		iSize	-= szBlock;
	}

	//Padding処理(PKCS#7)を実施
	ptPadding	= n + ((n%szBlock)?-1:szBlock-1);
	cPadData	= szBlock - iSize;
	cntPadData	= cPadData;
	do{
		cData[ptPadding] = cPadData;
		ptPadding--;
		cntPadData--;
	} while(cntPadData>0);

	//暗号（最終）
	if(iSize == szBlock){
		encrypt(&cData[n]);
		n += szBlock;
	}
	encrypt(&cData[n]);
	n += szBlock;

	return(cPadData);
}
//==============================================================
//			暗号文の入力
//--------------------------------------------------------------
//	●引数
//			void			*data	暗号文
//			unsigned int	iSize	暗号文のサイズ
//	●返値
//			無し
//==============================================================
void	Encryption::decipher(void *data,unsigned int iSize)
{
	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	while(n < iSize){
		decrypt(&cData[n]);
		n	+=	szBlock;
	}
}
//==============================================================
//			暗号文の入力（最終）
//--------------------------------------------------------------
//	●引数
//			void			*data	暗号文
//			unsigned	int	iSize	暗号文のサイズ
//	●返値
//						int	1～szBlock	Paddingデータ
//							-1			Paddingが異常
//==============================================================
int		Encryption::decipher_last(void *data,unsigned int iSize)
{
	unsigned	char*	cData		= (unsigned	char*)data;
	unsigned	int		n			= 0;

	unsigned	char	cPadData;
	unsigned	char	cntPadData;

	//復号
	while(iSize > 0){
		decrypt(&cData[n]);
		n		+= szBlock;
		iSize	-= szBlock;
	}

	//最後のBlockは、Paddingを含む。
	n--;
	cPadData	= cData[n];
	cntPadData	= cPadData;

	//Paddingのチェック
	do{
		if(cData[n] != cPadData){	return(-1);	}
		n--;
		cntPadData--;
	} while(cntPadData>0);
	return(cPadData);
}
