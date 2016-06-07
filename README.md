# SHAtwo
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
