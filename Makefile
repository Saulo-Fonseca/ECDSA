Ecdsa:	ecdsa.cpp SHA256.h SHA256.cpp RIPEMD160.h RIPEMD160.cpp GaloisField.hpp
	g++ -I. -Wunused -Wunreachable-code -Wall -std=c++11 -lgmpxx -lgmp *.cpp -o Ecdsa
