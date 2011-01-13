
#include "stdafx.h"

//==============================================================
//		�I�v�V��������
//--------------------------------------------------------------
//	������
//			int argc		�I�v�V����������̐�
//			_TCHAR* argv[]	�I�v�V����������
//	���Ԓl
//			SMF.name[]		�ϊ�����SMF�t�@�C��
//			MML.name[]		�ϊ����MML�t�@�C��
//	�����l
//			�I�v�V�����Ƀt�@�C�������w�肳��Ȃ��ꍇ�́A�w���v�\�����ďI��
//==============================================================
OPSW::OPSW(int argc, _TCHAR* argv[]):
	//�������ݒ�
	fHelp(0),		//�w���v�́A�f�t�H���g�͕\�����Ȃ��B
	cDecode(1),		//�Ńo�b�O
	iKey(256)		//���͎w��
	{

	//----------------------------------
	//��Local �ϐ�
	int		iCount;				//while�̃J�E���g�p
	int		iResult;

	//Option�����p
	int		iOptionChk;			//�I�v�V�����`�F�b�N�p�@�|�C���^
	char	cOption;			//�I�v�V�����`�F�b�N�p�@����
	char	iFlagFilnameExt;	//�g���q���������̃t���O

	//----------------------------------
	//���I�v�V��������
	iCount=1;	//�R�}���h���͔�΂�
	while(iCount!=argc)
	{
		//--------------
		//�I�v�V�����X�C�b�`�ɃX���b�V�������邩�m�F
		if((argv[iCount][0]=='/')||(argv[iCount][0]=='-')){

			//--------------
			//��Option Switch	�i�X���b�V�����������ꍇ�̏����j
			switch(argv[iCount][1]){
				//--------
				//Help�\��
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
				//���̎w��
				case 'K' :
					iResult=sscanf_s(argv[iCount],"/K%d",&iKey);
					if((iResult==NULL)||(iResult==EOF)){
						opError("/K");
						break;
					};
					if((iKey!=0)&&(iKey!=128)&&(iKey!=192)&&(iKey!=256)){
						opError("/K ���Ή��̌����ł��B");
						break;
					}
					break;
				//--------
				//�t�@�C���̎w��
				case 'F' :
					//��ɁA�t�@�C�����������Ă��邩�`�F�b�N�B
					if(argv[iCount][3]==0){
						opError("/F �t�@�C�����������Ă���܂���B");
						break;
					};
					switch(argv[iCount][2]){
						//--------
						//�Í����t�@�C���̎w��
						case 'c' :
							//���Ɏw�肳��Ă���H
							if(strAESname.empty()){
								iFlagFilnameExt=0;		//�g���q�̗L���@Reset
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
								opError("/F �Í����t�@�C����2��ȏ�w�肳��܂����B");
								break;
							};
							break;
						//--------
						//�Í����t�@�C���̎w��
						case 'k' :
							//���Ɏw�肳��Ă���H
							if(strKEYname.empty()){
								iKey = 0;				//�����w�肳�ꂽ�B
								iFlagFilnameExt=0;		//�g���q�̗L���@Reset
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
								opError("/F �Í����t�@�C����2��ȏ�w�肳��܂����B");
								break;
							};
							break;
						default :
							opError("/F");
							break;
					};
					break;
				//--------
				//�f�t�H���g
				default :
					opError("");
					break;
			};

		} else{

			//--------------
			//���t�@�C����	�i�X���b�V�������������ꍇ�̏����j
			//���Ɏw�肳��Ă���H
			if(strBINname.empty()){
				iFlagFilnameExt=0;		//�g���q�̗L���@Reset
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
				opError("�����t�@�C����2��ȏ�w�肳��܂����B");
				break;
			};

		};

		//--------------
		//�����̃I�v�V����
		iCount++;
	};

	//----------------------------------
	//���I�v�V�����Ŏw�肳�ꂽ������������B

	//--------------
	//�w���v�\��
	//�t�@�C������������Ȃ������ꍇ���A�w���v��\������B
	if((fHelp==1)||(strBINname.empty())){print_help();};

	//--------------
	//�o�̓t�@�C���̎w�肪���������ꍇ
	if(strAESname.empty()){
		strAESname = strBINname;
		strAESname+=".aes";
	};

	//--------------
	// �� �t�@�C���̎w�肪���������ꍇ
	if(strKEYname.empty()){
		strKEYname = strBINname;
		strKEYname+=".key";
	};

	//--------------
	//

	//	to do	���̑��̃I�v�V������ǉ������Ƃ��́A���̕ӂɒǋL����B

	//----------
	//Debug�p �\��
//	cout << "Plain-Text	= " << strBINname << endl;
//	cout << "Chiper-Text	= " << strAESname << endl;
//	cout << "Chiper-Key	= " << strKEYname << endl;

};
//==============================================================
//		�f�X�g���N�g
//--------------------------------------------------------------
//	������
//			�Ȃ�
//	���Ԓl
//			����
//==============================================================
OPSW::~OPSW(){

};
//==============================================================
//		�w���v���b�Z�[�W
//--------------------------------------------------------------
//	������
//			�Ȃ�
//	���Ԓl
//			����
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
//		�G���[����	�i�v���Z�X���I������j
//--------------------------------------------------------------
//	������
//			char *stErrMsg	�G���[���b�Z�[�W
//	���Ԓl
//			����
//==============================================================
void OPSW::opError(const char *stErrMsg){

	cerr << "�I�v�V�������s���ł��B�F" << stErrMsg << endl;
	exit(EXIT_FAILURE);

};
