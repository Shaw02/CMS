#pragma once

/****************************************************************/
/*			定数定義											*/
/****************************************************************/
/* Period parameters */  
#define	N			624
#define	M			397
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
	unsigned	long	mt[N];		/* the array for the state vector  */
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

