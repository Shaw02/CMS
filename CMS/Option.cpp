
#include "stdafx.h"

//==============================================================
//		�R���X�g���N�^�i�I�v�V���������j
//--------------------------------------------------------------
//	������
//			int			argc		�I�v�V����������̐�
//			_TCHAR*		argv[]		�I�v�V����������
//	���Ԓl
//			����
//	�����l
//			�I�v�V�����Ƀt�@�C�������w�肳��Ȃ��ꍇ�́A�w���v�\�����ďI��
//==============================================================
OPSW::OPSW(int argc, _TCHAR* argv[]):
	//�������ݒ�
	fHelp(0),			//�w���v�́A�f�t�H���g�͕\�����Ȃ��B
	cDecipher(1),		//�������[�h
	iCount(1000),
	iMode(5),			//����Default = 42
	iType(3)			
	{

	//----------------------------------
	//��Local �ϐ�
	int		iCount;				//while�̃J�E���g�p
	int		iResult;

	//Option�����p
	int		iOptionChk;			//�I�v�V�����`�F�b�N�p�@�|�C���^
	char	cOption;			//�I�v�V�����`�F�b�N�p�@����
	char	iFlagFilnameExt;	//�g���q���������̃t���O

	//----------------------------------------------------
	//SIMD���߂̃`�F�b�N
	fSIMD = ChkSIMD();
	switch(fSIMD){
		case(1):
			cout << "Detect SSE2 instruction sets." << endl;
			break;
		case(2):
			cout << "Detect AES-NI instruction sets." << endl;
			break;
		default:
			cout << "SIMD instruction do not found." << endl;
			exit(-1);
			break;
	}

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
				case 'd' :
				case 'D' :
					cDecipher = 1;
					break;
				//--------
				//Decode
				case 'e' :
				case 'E' :
					cDecipher = 0;
					break;
				//--------
				//�t�@�C���̎w��
				case 'T' :
					iResult=sscanf_s(argv[iCount],"/T%d",&iType);
					if((iResult==NULL)||(iResult==EOF)){
						opError("/T");
						break;
					};
					break;
				//--------
				//���̎w��
				case 'M' :
					iResult=sscanf_s(argv[iCount],"/M%d",&iMode);
					if((iResult==NULL)||(iResult==EOF)){
						opError("/M");
						break;
					};
					break;
				//--------
				//�p�X���[�h�̎w��
				case 'w' :
				case 'W' :
					//��ɁA�L�[���[�h�������Ă��邩�`�F�b�N�B
					if(argv[iCount][2]==0){
						opError("/W None pass-word.");
						break;
					};
					//���Ɏw�肳��Ă���H
					if(strKeyWord.empty()){
						iOptionChk=0;
						while((cOption=argv[iCount][iOptionChk+2])!=0)
						{
							strKeyWord+=cOption;
							iOptionChk++;
						};
					} else {
						opError("/W Too many pass word.");
						break;
					};
					break;
				//--------
				//�t�@�C���̎w��
				case 'f' :
				case 'F' :
					//��ɁA�t�@�C�����������Ă��邩�`�F�b�N�B
					if(argv[iCount][3]==0){
						opError("/F None file-name.");
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
									strAESname+=".p7";
								};
							} else {
								opError("/F Too many cipher-file-name.");
								break;
							};
							break;
						//--------
						//�Í����t�@�C���̎w��
						case 'k' :
							//���Ɏw�肳��Ă���H
							if(strKEYname.empty()){
								iMode = -1;				//�����w�肳�ꂽ�B
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
								opError("/F Too many cipher-key.");
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
				opError("Too many plain-file-name.");
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
		strAESname+=".p7";
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
//		�f�X�g���N�^
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
//			����
//	���Ԓl
//			����
//==============================================================
void	OPSW::print_help(){

	cout	<<	"CMS�iRFC.5652 �� PKCS#7�jutility\n"
				"Copyright (C) S.W. (A.Watanabe) 2011-2013\n"
				"\n"
				"CMS [ /options ] [filename]\n"
				"\n"
				"  --- Common option ---\n"
				"  filename		File name of Plain-Text.\n"
				"  /Fc[file(.p7 )]	File name of Cipher-Text. (Default = [filename].p7)\n"
				"  /Fk[file(.key)]	File name of Cipher-Key. (Default = [filename].key)\n"
				"  /W[PW]		Cipher-Key is SHA-256 hash of this PW(Pass Word).\n"
				"  /H			help\n"
				"  /T[n]			Type.\n"
				"			   3 : Enveloped Data(default)\n"
				"			   6 : Encryption Data\n"
				"\n"
				"  --- Decipher option ---\n"
				"  /D			Decipher (Default)\n"
				"\n"
				"  --- Encipher option ---\n"
				"  /E			Encipher\n"
				"  /M[n]			Block cipher modes of operation.\n"
				"			   1 : DES-CBC\n"
				"			   2 : 3-DES-CBC\n"
				"			   3 : AES-CBC 128-bit\n"
				"			   4 : AES-CBC 192-bit\n"
				"			   5 : AES-CBC 256-bit(default)\n" << endl;

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
