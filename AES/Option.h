
#pragma once

/****************************************************************/
/*																*/
/*			�N���X��`											*/
/*																*/
/****************************************************************/
class OPSW {
public:
	unsigned	int			iKey;			//��
	unsigned	char		cDecode;		//����
	unsigned	char		fHelp;			//�w���v���w�肵�����H
				string		strBINname;		//�w�肵�����̓t�@�C����
				string		strAESname;		//�w�肵���Í��t�@�C����
				string		strKEYname;		//�w�肵�� �� �t�@�C����

		OPSW();								//�������̂�
		OPSW(int argc, _TCHAR* argv[]);		//�������e����A�N���X�����������t�@�C���I�[�v��
		~OPSW();							//�t�@�C���N���[�Y
void	opError(const char *stErrMsg);		//�I�v�V�����G���[
void	print_help();						//�w���v
};
