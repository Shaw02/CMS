#pragma once

class FileInput :
	public ifstream
{
public:
		FileInput(const char*	strFileName);
		~FileInput(void);
void	fileopen(const char*	strFileName);
void	StreamPointerAdd(__int32 iSize);
void	StreamPointerMove(__int32 iSize);
unsigned	char	cRead();		//1[Byte] (little enfian) Read
unsigned	__int16	i16Read();		//2[Byte] (little enfian) Read
unsigned	int		GetSize();
};
