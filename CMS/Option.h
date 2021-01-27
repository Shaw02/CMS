#pragma once

/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class OPSW {
public:
//--------------
//�ϐ�
				int			cpuinfo[4];		//cpuid eax=1�̓��e
				int			iMode;			//�Í����p���[�h
				int			iType;			//�t�@�C���^�C�v
				int			iCount;			//�J��Ԃ���
				char		cDecipher;		//�����H
	unsigned	char		fHelp;			//�w���v���w�肵�����H

				string		strBINname;		//�w�肵�����̓t�@�C����
				string		strAESname;		//�w�肵���Í��t�@�C����
				string		strKEYname;		//�w�肵�� �� �t�@�C����
				string		strKeyWord;		//�Í����𕶎���Ŏw��B

//--------------
//�֐�
		OPSW();								//�������̂�
		OPSW(int argc, _TCHAR* argv[]);		//�������e����A�N���X�����������t�@�C���I�[�v��
		~OPSW();							//�t�@�C���N���[�Y
void	opError(const char *stErrMsg);		//�I�v�V�����G���[
void	print_help();						//�w���v
bool	chkSSE2(){return((cpuinfo[3] & 0x04000000) != 0);};
bool	chkAESNI(){return((cpuinfo[2] & 0x02000000) != 0);};
};
