// stdafx.h : �W���̃V�X�e�� �C���N���[�h �t�@�C���̃C���N���[�h �t�@�C���A�܂���
// �Q�Ɖ񐔂������A�����܂�ύX����Ȃ��A�v���W�F�N�g��p�̃C���N���[�h �t�@�C��
// ���L�q���܂��B
//

#pragma once

#include "targetver.h"

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <nmmintrin.h>

#include <string>
#include <iostream>
#include <fstream>

// TODO: �v���O�����ɕK�v�Ȓǉ��w�b�_�[�������ŎQ�Ƃ��Ă��������B

using namespace std;

#include "option.h"			//�I�v�V��������
#include "FileInput.h"		//�I�v�V��������
#include "FileOutput.h"		//�I�v�V��������

#include "AES.h"		//AES�Í�
#include "MT.h"			//MT����


void	dataPrint(int n, void *Data);
