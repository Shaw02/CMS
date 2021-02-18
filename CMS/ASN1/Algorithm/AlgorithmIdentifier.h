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
//	各アルゴリズムの基底クラスです。
//
//======================================================================
/****************************************************************/
/*			クラス定義											*/
/****************************************************************/
class AlgorithmIdentifier :
	public Sequence
{
public:
//--------------
//変数
/*
AlgorithmIdentifier ::= SEQUENCE  {
  algorithm OBJECT IDENTIFIER,
  parameters ANY DEFINED BY algorithm OPTIONAL  }
*/
	ObjectIdentifier	algorithm;

//--------------
//関数
						AlgorithmIdentifier(const char _strName[]="AlgorithmIdentifier");
						~AlgorithmIdentifier(void);

				void	Set_oid(unsigned int i[], size_t n);
				void	Set();
				int		Check_OID(ObjectIdentifier* ptOID);
};
