#pragma once

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class FileOutput :
	public ofstream
{
//--------------
//•Ï”

//--------------
//ŠÖ”
public:
		FileOutput(const char*	strFileName);
		~FileOutput(void);
void	fileopen(const char*	strFileName);
void	StreamPointerAdd(__int32 iSize);
void	StreamPointerMove(__int32 iSize);
};
