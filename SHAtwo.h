/* //////////////////////////////////

	SHAtwo.h
	
	This is an implementation of the popular SHA-512 hash function.
	Written in a convenient class form for speedy deployment.
	The digest is stored in an array of 8 unsigned "long long"
	integers within the class. For convenient retrieval of the 
	digest, use member function `GetDigest()`   
	
	The following four member functions are set public for developers 
	who want to deploy this class.
	
		HashText()   
		HashData()
		GetDigest()
		SetTotalRounds()
		
	HashText()   
		This expects a c-style string as an argument. 
		Your string must fit in memory, and be less than 4.2 GB.
		
	HashData()
		Expects an array of unsigned bytes and a specified size.
		Your data must fit in memory, and be less than 4.2 GB.
	
	GetDigest()
		The output digest will be 512 bits, which will
		be copied into array of 64 bytes. 
		
	SetTotalRounds()
		Default is 80.  Change for more or less rounds in the 
		principle pipeline.
		
		
_ Notes on Precise size limits _
HashText(), maximum input string length: 4,294,967,284 characters.
HashData(), maximum data size: 4,294,967,286 bytes.
		
/////////////////////////////////////// */



#define ubyte8_t 		unsigned char
#define shr(x,n) 		((x & 0xFFFFFFFFFFFFFFFFULL) >> n)
#define rotr(x,n) 		(shr(x,n) | (x << (64 - n)))
#define ChanSplit(W,a,b,c,d)		{a=(W>>24)&(0xFF);b=(W>>16)&(0xFF);c=(W>>8)&(0xFF);d=(W)&(0xFF);}
#define ChanCombine(W,a,b,c,d)		{W=(a<<24)|(b<<16)|(c<<8)|(d);}

typedef unsigned long long ullint;

class shaBlock {
public:
	ullint W[80];	
	unsigned curW;
	unsigned curbyte;	
	
public:
	void WipeZero(void);
	void Concatenate(ubyte8_t uc);
	void ConcatenateFaster(ubyte8_t * uc_arr);
};



class SHAtwo {
// Dependent Classes.
public:
	shaBlock	streamblock;
	shaBlock	finalblock;	

// Data area. 	
	ullint		iv_H[8];
	ullint		H[8];
	ullint		K[80];
	uint32_t	msgcnt;
	uint32_t	msg_i;
	uint32_t	num_blk;
	bool		tailbit;
	int			roundmax;

// Database links juggling area.
	ullint * ptr_K;
	ullint * ptr_H;

// Functionality
public:
    SHAtwo();
    ~SHAtwo();
    
    void		DuplicateDatabase(void);
    void		HashText(char * mtxt );
	void		HashData(ubyte8_t * mdat, uint32_t Ldat );
	void		SetTotalRounds(int stot);
	void		GetDigest(ubyte8_t * udig );   
   	 
private:		
	void			EightyRounds(char selblk);
	void			PrintSixtyFour(ullint psf);
	inline ullint 	ch(ullint x, ullint y, ullint z);
	inline ullint 	maj(ullint x, ullint y, ullint z);
	inline ullint 	fn0(ullint x);
	inline ullint   fn1(ullint x);
	inline ullint 	sigma0(ullint x);
	inline ullint 	sigma1(ullint x);
};



inline ullint SHAtwo
::ch(ullint x, ullint y, ullint z)
{
 	return (
	 	(x&y) ^ (~x&z)
	);
}


inline ullint SHAtwo
::maj(ullint x, ullint y, ullint z)
{
 	return ( 
 		(x&y) ^ (y&z) ^ (z&x)	
	);
}


inline ullint SHAtwo
::fn0(ullint x)
{
 	return ( 
	 	rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)	
		 );
}


inline ullint SHAtwo
::fn1(ullint x)
{
 	return ( 
	 	rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
	);
}


inline ullint SHAtwo
::sigma0(ullint x)
{
	return (
	 	rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7)
	 );
}


inline ullint SHAtwo
::sigma1(ullint x)
{
	return ( 
		rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6)
	);
}

