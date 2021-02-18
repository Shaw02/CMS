#pragma once
#include "..\Sequence.h"

//======================================================================
//					Algorithm Identifier
//----------------------------------------------------------------------
//	Reference:
//	RFC 5280		Internet X.509 Public Key Infrastructure Certificate
//					and Certificate Revocation List (CRL) Profile
//======================================================================
//
//	�e�A���S���Y���̊��N���X�ł��B
//
//======================================================================
/****************************************************************/
/*			�N���X��`											*/
/****************************************************************/
class AlgorithmIdentifier :
	public Sequence
{
public:
//--------------
//�ϐ�
/*
AlgorithmIdentifier ::= SEQUENCE  {
  algorithm OBJECT IDENTIFIER,
  parameters ANY DEFINED BY algorithm OPTIONAL  }
*/
	ObjectIdentifier	algorithm;

//--------------
//�֐�
						AlgorithmIdentifier(const char _strName[]="AlgorithmIdentifier");
						~AlgorithmIdentifier(void);

				void	Set_oid(unsigned int i[], size_t n);
				void	Set();
				int		Check_OID(ObjectIdentifier* ptOID);
};
