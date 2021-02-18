#pragma once

/****************************************************************/
/*			ƒNƒ‰ƒX’è‹`											*/
/****************************************************************/
class FileInput :
	public ifstream
{
//--------------
//•Ï”

//--------------
//ŠÖ”
public:
		FileInput(const char*	strFileName);
		~FileInput(void);
void	fileopen(const char*	strFileName);
void	StreamPointerAdd(std::streamoff iSize);
void	StreamPointerMove(std::streamoff iSize);
unsigned	char	cRead();		//1[Byte] (little enfian) Read
unsigned	__int16	i16Read();		//2[Byte] (little enfian) Read
std::streamoff		GetSize();
};
