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



#include <stdint.h>
#include<cstring>
#include<iostream>
#include<vector>
#include<fstream>
#include<string>
#include "SHAtwo.h"
#include "SHAtwoDATABASE.h"


using namespace std;




void shaBlock
::WipeZero(void)
{
	int	n;
	curW 	=
	curbyte =0;	
	n=0;
	while(n<80) {
		W[n] = (ullint)(0x0000);
		n++;
	}
}


// * //
void shaBlock
::Concatenate(ubyte8_t uc)
{
	ullint		omega;
	ullint 		SFupper, SFlower;
	uint32_t	wupper, wlower;
	uint32_t	A,B,C,D;
	
	omega = W[curW];
	wupper = (uint32_t)(omega>>32);
	wlower = (uint32_t)(omega & (0xFFFFFFFF));
	
	if( curbyte < 4 ) {
		ChanSplit(wupper,A,B,C,D);
		switch(curbyte) {
			case 0: A = (uint32_t)uc; break;
			case 1: B = (uint32_t)uc; break;
			case 2: C = (uint32_t)uc; break;
			case 3: D = (uint32_t)uc; break;				
		}
		ChanCombine(wupper,A,B,C,D);
	}  else {
		ChanSplit(wlower,A,B,C,D);
		switch(curbyte) {
			case 4: A = (uint32_t)uc; break;
			case 5: B = (uint32_t)uc; break;
			case 6: C = (uint32_t)uc; break;
			case 7: D = (uint32_t)uc; break;
		}
		ChanCombine(wlower,A,B,C,D);
	}
	
	SFupper = (ullint)wupper;
	SFlower = (ullint)wlower;
	
	omega = (SFupper<<32) | (SFlower);
	W[curW] = omega;
		
	if( curbyte == 7 ) curW++;
	curbyte = (curbyte+1)%8;	
}

// * //
void shaBlock
::ConcatenateFaster(ubyte8_t * uc_arr)
{	
	ullint 		SFupper, SFlower;
	uint32_t	wupper, wlower;
	//.	
	ChanCombine(wupper, uc_arr[0],
						uc_arr[1],
						uc_arr[2],
						uc_arr[3] );
	ChanCombine(wlower, uc_arr[4],
						uc_arr[5],
						uc_arr[6],
						uc_arr[7] );	
	SFupper = (ullint)wupper;
	SFlower = (ullint)wlower;	
	W[curW] = (SFupper<<32) | (SFlower);		
	curW++;
	//curbyte = (curbyte+8)%8; ?
}


/// * * ///



SHAtwo::SHAtwo()
{
	roundmax=80;
	ptr_H	=	(SHAtwoDB_H);
	ptr_K	=	(SHAtwoDB_K);
	DuplicateDatabase();
}

SHAtwo::~SHAtwo()
{
}

// * //
void SHAtwo
::DuplicateDatabase(void)
{
	int n;
	n=0;
	while(n<8) {
		iv_H[n] = ptr_H[n];	n++;
	}
	
	n=0;
	while(n<80) {
		K[n] = ptr_K[n]; n++;
	}
}


// * //
void SHAtwo
::HashText(char * mtxt )
{
	int n;
	ubyte8_t uchard;
	uint32_t blkrmn, datrmn, cur_blk, slack, last_strblk;
	ubyte8_t ardat[8];	
	bool streamcondi;
	//.
		
	
	msgcnt = (uint32_t)strlen(mtxt);
	
	num_blk = ((msgcnt+9) / 128);
	
	if(num_blk > 0) {
		slack = (msgcnt+9) % 128;
		if( slack > 0 ) {
			// Usually there will be slack.
			//  Slack takes up a whole block.
			num_blk ++; 
			streamcondi = true;
		} else {
			// Edge cases where the message aligns
			//  perfectly with a block boundary.
			if( num_blk > 1 ) {
				streamcondi= true;
			} else {
				//  num_blk==1, because (128/128)==1
				// Unusual case where the message fits 
				// perfectly into the first block.
				streamcondi = false;
			}
		}
	} else {
		// The message is smaller than a single block.
		streamcondi = false;
	}
	
	n=0;
	while(n<8) {
		H[n] = iv_H[n];
		n++;
	}
	tailbit = false;
	
	msg_i=0;	
	if( streamcondi ) {
		last_strblk = num_blk-1;
		cur_blk=0;
		while( cur_blk < last_strblk ) {
			streamblock.WipeZero();
			while( (streamblock.curW < 16    ) && 
				   (msg_i            < msgcnt) ) {
				   	
				if( (msgcnt-msg_i) > 7 ) {
					n=0;
					while(n<8){
						ardat[n] = (ubyte8_t)( mtxt[msg_i] );	
						msg_i++;
						n++;
					}				
					streamblock.ConcatenateFaster(ardat);
				} else {
					uchard = (ubyte8_t)	(mtxt[msg_i] );
					streamblock.Concatenate( uchard );
					msg_i++;
				}					
			}
			
			if( msg_i >= msgcnt ) {   // Did the loop above run out of message data?
				if( streamblock.curW < 16 )	{ // Is there room left over in this block?
					streamblock.Concatenate(0x80); // Append the tail 1-bit.
					tailbit = true;
				}
			}
			
			/*cout << endl;
			cout << "Block no. ";
			cout << cur_blk;
			cout << endl;*/			 
			
			EightyRounds('s');
			
			cur_blk++;
		}	
	}
	
	finalblock.WipeZero();
	while( msg_i  < msgcnt ) {
		if( (msgcnt-msg_i) > 7 ) {
			n=0;
			while(n<8){
				ardat[n] = (ubyte8_t)( mtxt[msg_i] );	
				msg_i++;
				n++;
			}				
			finalblock.ConcatenateFaster(ardat);
		} else {
			uchard = (ubyte8_t)	(mtxt[msg_i] );
			finalblock.Concatenate( uchard );
			msg_i++;
		}					
	}
	
	/*cout << endl;
	cout << "Final block.";
	cout << endl;*/
 
	
	EightyRounds('f');
}


// * //
void SHAtwo
::HashData(ubyte8_t * mdat, uint32_t Ldat )
{
	int n;
	uint32_t blkrmn, datrmn, cur_blk, slack, last_strblk;
	ubyte8_t ardat[8];
	bool streamcondi;
	//.	
	
	msgcnt = Ldat;
	num_blk = ((msgcnt+9) / 128);
	if(num_blk > 0) {
		slack = (msgcnt+9) % 128;
		if( slack > 0 ) {
			// Usually there will be slack.
			//  Slack takes up a whole block.
			num_blk ++; 
			streamcondi = true;
		} else {
			// Edge cases where the message aligns
			//  perfectly with a block boundary.
			if( num_blk > 1 ) {
				streamcondi= true;
			} else {
				//  num_blk==1, because (128/128)==1
				// Unusual case where the message fits 
				// perfectly into the first block.
				streamcondi = false;
			}
		}
	} else {
		// The message is smaller than a single block.
		streamcondi = false;
	}
	
	n=0;
	while(n<8) {
		H[n] = iv_H[n];
		n++;
	}
	tailbit = false;
	
	msg_i=0;	
	if( streamcondi ) {
		last_strblk = num_blk-1;
		cur_blk=0;
		while( cur_blk < last_strblk ) {
			streamblock.WipeZero();
			while( (streamblock.curW < 16    ) && 
				   (msg_i            < msgcnt) ) {
				   	
				if( (msgcnt-msg_i) > 7 ) {
					n=0;
					while(n<8){
						ardat[n] = mdat[msg_i];	
						msg_i++;
						n++;						
					}				
					streamblock.ConcatenateFaster(ardat);					
				} else {
					streamblock.Concatenate( mdat[msg_i] );
					msg_i++;
				}					
			}
			
			if( msg_i >= msgcnt ) {   // Did the loop above run out of message data?
				if( streamblock.curW < 16 )	{ // Is there room left over in this block?
					streamblock.Concatenate(0x80); // Append the tail 1-bit.
					tailbit = true;
				}
			}
			
			/*cout << endl;
			cout << "Block no. ";
			cout << cur_blk;
			cout << endl;*/
		
			EightyRounds('s');
			
			cur_blk++;
		}	
	}
	
	finalblock.WipeZero();
	while( msg_i  < msgcnt ) {				   	
		if( (msgcnt-msg_i) > 7 ) {
			n=0;
			while(n<8){
				ardat[n] = mdat[msg_i];	
				msg_i++;
				n++;
			}				
			finalblock.ConcatenateFaster(ardat);			
		} else {
			finalblock.Concatenate( mdat[msg_i] );
			msg_i++;
		}					
	}
	
	/*cout << endl;
	cout << "Final block.";
	cout << endl;*/

	EightyRounds('f');	
}



void SHAtwo
::EightyRounds(char selblk)
{
	int j,round, smod;
	ullint t1,t2,longmsgcnt;
	ullint work[8];
	ullint * Wp;	
	//.
	
	
	if( selblk == 'f' ) {
		if( !tailbit ) {
			// The 1-bit tail was bumped up to this block.  Append it now.
			// This may also happen when the message is the empty string, ""
			finalblock.Concatenate(0x80);
			tailbit = true;
		}
		longmsgcnt = (ullint)msgcnt;
		longmsgcnt = longmsgcnt *8;
		finalblock.W[15] = longmsgcnt; 
		Wp = finalblock.W;
	} else {
		Wp = streamblock.W;
	}
	
	/*
	j=0;
	while(j<16) {
		cout << "W[";
		cout << j;
		cout << "] = ";
		PrintSixtyFour( Wp[j] );
		cout << endl;
		j++;
	}
	*/
	
	
	j=16;
	while(j<80) {	
		Wp[j] = sigma1(Wp[j-2 ]) + 
		               Wp[j-7 ]  + 
			    sigma0(Wp[j-15]) + 
			           Wp[j-16];
		j++;
	}
	
	j=0;
	while(j<8){	
		work[j] = H[j]; 
		j++;
	}
	
	round=0;
	while( round < roundmax ) 
	{
		smod = round%80;
		
		t1 =     work[7]  + 
			 fn1(work[4]) + 
			 ch( work[4], work[5], work[6]) + 
			  K[smod] + 
			 Wp[smod];
		t2 = fn0(work[0]) + 
		 	 maj(work[0], work[1], work[2]);
		 		
		work[7] = work[6];
		work[6] = work[5];
		work[5] = work[4];
		work[4] = work[3] + t1; 
		work[3] = work[2]; 
		work[2] = work[1];
		work[1] = work[0];
		work[0] = t1 + t2;
		round++;
	}
	
	j=0;
	while(j<8) {
		H[j] = H[j] + work[j]; 
		j++;
    }	
}


// * //
void SHAtwo
::GetDigest(ubyte8_t * udig )
{
	ullint ulH;
	int n, d;
	uint32_t hiH, loH, A,B,C,D;
	//.
	
	d=n=0;
	while(n<8) {
		ulH = H[n];
		hiH = (uint32_t)(ulH>>32);
		loH = (uint32_t)(ulH & (0xFFFFFFFF));
		ChanSplit(hiH,A,B,C,D);
		udig[d  ] = (ubyte8_t)A;
		udig[d+1] = (ubyte8_t)B;
		udig[d+2] = (ubyte8_t)C;
		udig[d+3] = (ubyte8_t)D;
		ChanSplit(loH,A,B,C,D);
		udig[d+4] = (ubyte8_t)A;
		udig[d+5] = (ubyte8_t)B;
		udig[d+6] = (ubyte8_t)C;
		udig[d+7] = (ubyte8_t)D;
		d += 8;	
		n++;
	}
}


void SHAtwo
::SetTotalRounds(int stot) { roundmax = stot; }

void SHAtwo
::PrintSixtyFour(ullint psf)
{
	uint32_t  wupper, wlower;
	wupper = (uint32_t) ( psf >> 32 );
	wlower = (uint32_t) ( psf & (0xFFFFFFFF));
	//cout << std::hex << std::setw(8) << std::setfill('0');
	//cout << wupper;
	//cout << wlower;
	//cout << std::dec;
}

