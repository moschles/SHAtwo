#include <stdint.h>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <string>
#include "SHAtwo.h"


using namespace std;

typedef unsigned int uint;


// Functions //
void 		HexASCII(char * csty );
void 		HexASCII(ubyte8_t * csty, uint32_t len );


void HexASCII(char * csty ){
	unsigned char uc;
	int len, r, clue;
	//.
	
	len = strlen(csty);
	
	if( len==0) {
		cout << "(empty string)";
	}
	
	r=0;
	while(r<len) {
		if( (r%16)==0 ) {
			cout << endl;
		}
		uc = (unsigned char)csty[r];
		clue = (int)uc;
		cout << std::hex << std::setw(2) << std::setfill('0');
		cout << clue;
		r++;
	}
	cout << endl;
	cout << std::dec;
}

void HexASCII(ubyte8_t * csty, uint32_t len ){
	unsigned char uc;
	uint32_t r;
	int clue;
	//.
	
	if( len==0) {
		cout << "(empty string)";
	}
	
	r=0;
	while(r<len) {
		if( (r%16)==0 ) {
			cout << endl;
		}
		clue = (int)(csty[r]);
		cout << std::hex << std::setw(2) << std::setfill('0');
		cout << clue;	
		r++;
	}
	cout << endl;
	cout << std::dec;
}


void PrintSixtyFour(ullint psf)
{
	//
	uint32_t  wupper, wlower;
	wupper = (uint32_t) ( psf >> 32 );
	wlower = (uint32_t) ( psf & (0xFFFFFFFF));
	cout << std::hex << std::setw(8) << std::setfill('0');
	cout << wupper;
	cout << wlower;
	cout << std::dec;
}
 
 
 
 
 
int main(int argc, char** argv) 
{	
	SHAtwo 		sha512;
	SHAtwo 		sha512dat;
	uint 		i,t;
	char 		cmessage[800];
	ubyte8_t 	datamsg[800];
	ubyte8_t 	udigest[70];
	 //.
	
 


/*
	strcpy(cmessage,
"Long ago, when Japanese goddess Amaterasu and her group traveled around at the boundary of Yakami in Inaba, they were\
looking for a place for their temporary palace, suddenly a white hare appeared. The white hare bit Amaterasu's clothes\
and took her to an appropriate place for a temporary palace along Nakayama mountain and Reiseki mountain. About two\
 hours' walk, accompanied by the white hare, the Amaterasu group reached a mountain top plain, which is now called Ise\
ga naru. Then, the white hare disappeared at Ise ga naru.");
*/

	strcpy(cmessage, "The quick brown fox jumps over the lazy dog." );
	cout << cmessage << endl;
	HexASCII(cmessage);
	
	
	t=strlen(cmessage);
	i=0;
	while(i<t) {
		datamsg[i] = (ubyte8_t)cmessage[i];
		i++;
	}
	
	
	 
	sha512.HashText(cmessage);
	sha512.GetDigest(udigest);
	cout<<endl<<endl<<endl<<"****************SHA 512 DIGEST IN HEX (text)****************"<<endl;
	HexASCII(udigest,64);	
	
	 
	sha512.HashData(datamsg,t);
	sha512.GetDigest(udigest);
	cout<<endl<<endl<<endl<<"****************SHA 512 DIGEST IN HEX (data)****************"<<endl;
	HexASCII(udigest,64);	
	
	return 0;
}
