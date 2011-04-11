#pragma once

/*
	This is class version of Mersenne Twister.
	Changed by A.Watanabe
*/


/*
   A C-program for MT19937, with initialization improved 2002/1/26.
   Coded by Takuji Nishimura and Makoto Matsumoto.

   Before using, initialize the state by using init_genrand(seed)  
   or init_by_array(init_key, key_length).

   Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
   All rights reserved.                          

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

     1. Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

     2. Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

     3. The names of its contributors may not be used to endorse or promote 
        products derived from this software without specific prior written 
        permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


   Any feedback is very welcome.
   http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
   email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)
*/

/****************************************************************/
/*			定数定義											*/
/****************************************************************/
/* Period parameters */  
#define	MT_N		624
#define	MT_M		397
#define MATRIX_A	0x9908b0dfUL		/* constant vector a */
#define UPPER_MASK	0x80000000UL		/* most significant w-r bits */
#define LOWER_MASK	0x7fffffffUL		/* least significant r bits */

/****************************************************************/
/*																*/
/*			クラス定義											*/
/*																*/
/****************************************************************/
class MT {

//メンバー変数
private:
	unsigned	long	mt[MT_N];	/* the array for the state vector  */
	unsigned	int		mti;		/* mti==N+1 means mt[N] is not initialized */
//メンバー関数
public:
						MT(void);
						MT(unsigned long init_key[], unsigned int key_length);
	void				init_genrand(unsigned long s);
	void				init_by_array(unsigned long init_key[], unsigned int key_length);
	unsigned	long	genrand_int32(void);

				long	genrand_int31(void)
				{
					/* generates a random number on [0,0x7fffffff]-interval */
					return (long)(genrand_int32()>>1);
				};

				/* generates a random number on [0,1]-real-interval */
				double	genrand_real1(void){
					return genrand_int32()*(1.0/4294967295.0); 
					/* divided by 2^32-1 */ 
				};

				/* generates a random number on [0,1)-real-interval */
				double	genrand_real2(void){
					return genrand_int32()*(1.0/4294967296.0); 
					/* divided by 2^32 */
				};

				/* generates a random number on (0,1)-real-interval */
				double	genrand_real3(void){
					return (((double)genrand_int32()) + 0.5)*(1.0/4294967296.0); 
					/* divided by 2^32 */
				};

				/* generates a random number on [0,1) with 53-bit resolution*/
				double	genrand_res53(void){ 
					unsigned long a=genrand_int32()>>5, b=genrand_int32()>>6; 
					return(a*67108864.0+b)*(1.0/9007199254740992.0); 
				};

};

