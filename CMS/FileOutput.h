#pragma once

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class FileOutput :
	public ofstream
{
//--------------
//�ϐ�

//--------------
//�֐�
public:
		FileOutput(const char*	strFileName);
		~FileOutput(void);
void	fileopen(const char*	strFileName);
void	StreamPointerAdd(std::streamoff iSize);
void	StreamPointerMove(std::streamoff iSize);
};
