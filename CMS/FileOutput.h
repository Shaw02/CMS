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
void	StreamPointerAdd(__int32 iSize);
void	StreamPointerMove(__int32 iSize);
};
