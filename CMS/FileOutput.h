#pragma once

/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class FileOutput :
	public ofstream
{
//--------------
//変数

//--------------
//関数
public:
		FileOutput(const char*	strFileName);
		~FileOutput(void);
void	fileopen(const char*	strFileName);
void	StreamPointerAdd(__int32 iSize);
void	StreamPointerMove(__int32 iSize);
};
