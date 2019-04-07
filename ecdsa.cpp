// Title: ECDSA File Signer
// Author: Saulo Fonseca <saulo@astrotown.de>
// Description: Signs and verifies a file using priv/pub bitcoin keys
// Dependencies: You need to install GMP library

#include <string>
#include <iostream>
#include <sys/ioctl.h>
#include <gmpxx.h>        // mpz_class (bignum)
#include <fcntl.h>        // O_RDONLY
#include <unistd.h>       // READ, CLOSE
#include <inttypes.h>     // printf uint64_t
#include <fstream>
#include "base64.h"
#include "SHA256.h"
#include "RIPEMD160.h"
#include "GaloisField.hpp"

using namespace std;

struct point
{
	GF x;
	GF y;
};

// Values for secp256k1
class Curve
{
public:
	mpz_class N;
	mpz_class P;
	point G;
	Curve() // Constructor
	{
		mpz_class N("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
		mpz_class P("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
		mpz_class x("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
		mpz_class y("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
		this->G.x = GF(x,P);
		this->G.y = GF(y,P);
		this->N = N;
		this->P = P;
	}
};
Curve secp256k1;

// Get n bytes from /dev/random as hex string
string readDevRandom(int n)
{
	// Define some vars
	string hex;
	char buf[3];
	bool success = false;

	// Open /dev/urandom
#ifdef __APPLE__
	// Apple /dev/random uses the Yarrow CSPRNG that does not offer an entropy check
	do
	{
		int rnd = open("/dev/random", O_RDONLY);
		if (rnd >=0)
		{
			unsigned char c;
			for (int i=0; i<n; i++)
			{
				read(rnd,&c,1);
				sprintf(buf,"%02hhx",c);
				hex += buf;
			}
			close(rnd);
			success = true;
		}
		else
		{
			cout << "/dev/random is not available or does not have enough entropy! Trying again..." << endl;
		}
	} while (success == false);
#else
	unsigned int entropy = 0;
	do
	{
		int rnd = open("/dev/random", O_RDONLY);
		if (rnd >=0 && !ioctl(rnd, 2147766784, &entropy) && (entropy >= 32))
		{
			unsigned char c;
			for (int i=0; i<n; i++)
			{
				read(rnd,&c,1);
				sprintf(buf,"%02hhx",c);
				hex += buf;
			}
			close(rnd);
			success = true;
		}
		else
		{
			cout << "/dev/random is not available or does not have enough entropy! Trying again..." << endl;
		}
	} while (success == false);
#endif
	return hex;
}

// Creates a random number with 256 bits
GF genPriv()
{
	// 1 < sk < N -1
	mpz_class key;
	do
	{
		key = mpz_class(readDevRandom(32),16);
	} while (key <= 0 || key >= secp256k1.N);
	return GF(key,secp256k1.P);
}

// Addition operation on the elliptic curve
// See: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_addition
point add(point p, point q)
{
	// Calculate lambda
	GF lambda;
	if (p.x == q.x && p.y == q.y)
	{
		lambda = ( p.x.pow(2) * 3 ) / ( p.y * 2 );
	}
	else
	{
		lambda = (q.y - p.y) / (q.x - p.x);
	}

	// Add points
	point r;
	r.x = lambda.pow(2) - p.x - q.x;
	r.y = lambda * (p.x - r.x) - p.y;
	return r;
}

// Convert private key to public
point priv2pub(GF sk, point *Q=NULL)
{
	// Copy generator
	point G;
	if (Q == NULL)
	{
		G.x = secp256k1.G.x;
		G.y = secp256k1.G.y;	
	}
	else
	{
		G.x = Q->x;
		G.y = Q->y;
	}

	// Compute G * sk
	point pub;
	pub.x = GF(0,secp256k1.P);
	pub.y = GF(0,secp256k1.P);
	mpz_class bit;
	bit = 1;
	for (int i=0; i<256; i++)
	{
		mpz_class cmp = 0;
		mpz_and (cmp.get_mpz_t(), bit.get_mpz_t(), sk.getNum().get_mpz_t());
		if (cmp != 0)
		{
			if (pub.x == 0 && pub.y == 0)
			{
				pub.x = G.x;
				pub.y = G.y;
			}
			else
			{
				pub = add(pub, G);
			}
		}
		G = add(G, G);
		bit = bit << 1;
	}
	return pub;
}

// Interface to external hash libraries
// function = 1, hash = SHA-256
// function = 2, hash = RIPEMP160
string getHash(string str, int function)
{
	// Convert string to uint8_t array
	int length = str.length() / 2;
	uint8_t *source = new uint8_t[length];
	for (int i=0; i<(int)str.length(); i+=2)
		source[i/2] = stoul(str.substr(i,2),nullptr,16);

	// Get hash of array
	int lenHash = 32;
	if (function == 2)
		lenHash = 20;
	uint8_t *hashBuf =  new uint8_t[lenHash];
	if (function == 1)
		computeSHA256(source, length, hashBuf);
	else if (function == 2)
		computeRIPEMD160(source, length, hashBuf);

	// Convert back to string
	char buf[3];
	string ret;
	for (int i=0; i<lenHash; i++)
	{
		sprintf(buf, "%02x", hashBuf[i]);
		ret += buf;
	}
	delete [] source;
	delete [] hashBuf;
	return ret;
}

// Add mainnet address and checksum
string mainnetChecksum(string mainnet, const string &key, bool compress)
{
	// mainnet  = 0x80 for private key and 0x00 for public key
	// key      = Hex 32 bytes for private key and 20 for ripemd160 for public
	// compress = If defined, generate the compressed form for private key
	mainnet += key;
	if (compress)
		mainnet += "01";
	string sha = getHash(getHash(mainnet,1),1); // sha256(sha256(x))
	string checksum = sha.substr(0,8);
	string newKey = mainnet+checksum;
	return newKey;
}

// Encode using Base58Check
string encodeBase58Check(string hex)
{
	// Define scope
	static string base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	// Find multiple rest of division by 58
	mpz_class dec(hex.c_str(), 16);
	static mpz_class mod = 58;
	string output = "";
	while (dec>0)
	{
		mpz_class remainder;
		mpz_mod(remainder.get_mpz_t(), dec.get_mpz_t(), mod.get_mpz_t());
		dec = (dec - remainder) / 58;
		output = base58[(int)remainder.get_ui()] + output;
 	}

	// Replace all leading zeros by 1
	while (hex.substr(0,2) == "00")
	{
		output = "1" + output;
		hex = hex.substr(2);
	}
	return output;
}

// Decode Base58 from WIF
string decodeBase58(string wif)
{
	// Define scope of Base58
	static string base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	// Recover hex from WIF
	mpz_class n = 0;
	while (wif.length() > 0)
	{
		n *= 58;
		int idx = base58.find(wif.substr(0,1));
		if (idx<0)
		{
			cout << "Wrong WIF format. This is not Base58!" << endl;
			return "";
		}
		n += idx;
		wif = wif.substr(1);
	}
	static char buf[77];
	gmp_sprintf(buf, "%Z076x", n.get_mpz_t());
	return buf;
}

// Remove mainnet and checksum
string remMainCheck(string hex)
{
	// Check if hex from WIF is compressed
	bool compressed = false;
	if (hex.substr(0,2) != "00")
		compressed = true;
	if (!compressed)
		hex = hex.substr(2);

	// Remove checksum
	string check = hex.substr(hex.length()-8);
	hex = hex.substr(0,hex.length()-8);
	string sha = getHash(getHash(hex,1),1); // sha256(sha256(x))
	string checksum = sha.substr(0,8);
	if (checksum != check)
		cout << "Checksum is wrong!" << endl;
	
	// Remove mainnet
	if (hex.substr(0,2) == "80")
		hex = hex.substr(2);
	else
		cout << "This is not a WIF!" << endl;

	// Remove compressed marker
	return hex.substr(0,64);
}

// Convert bitcon public address to base58Check
string binary2Addr(const string &str)
{
	// Empty argument generate key for 1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E
	string sha = getHash(str,1);
	string hexCheck = mainnetChecksum("00",getHash(sha,2),0); // ripemd160(sha256(x))
	return encodeBase58Check(hexCheck);
}

// Split X and Y values from public key
string splitXY(string key, point &pk)
{
	string x = key.substr(2,64);
	static mpz_class res;
	static mpz_class mod = 2;
	mpz_mod(res.get_mpz_t(), pk.y.getNum().get_mpz_t(), mod.get_mpz_t());
	if (res == 0)
		return "02" + x;
	return "03" + x;
}

// Read message file
string readFile(string file)
{
	// Read file
	string tmp = "";
	char buf[3];
	char c;
	int count = 0;
	ifstream input(file,ios::in | ios::binary);
	if (!input)
	{
		cout << file << " file is not available." << endl;
		exit(1);
	}
	while (input.get(c))
	{
		sprintf(buf,"%02x",c);
		tmp += buf;
		count++;
	}
	input.close();
	return tmp;
}

// Convert hex byte from string to int
int hex2int(string h)
{
	char byte[3];
	unsigned int hex;
	byte[2] = 0;
	byte[0] = h[0];
	byte[1] = h[1];
	byte[2] = 0;
	sscanf(byte,"%x",&hex);
	return (signed int)hex;
}

int main(int argc, char **argv)
{
	// Check parameters
	if ( !( (argc == 4 and string(argv[1]) == "sign") or
			(argc == 5 and string(argv[1]) == "verify") ) )
	{
		cout << "ECDSA signature utility" << endl;
		cout << "Usage: ./Ecdsa sign   <fileToBeSigned>  <WIF>" << endl;
		cout << "       ./Ecdsa verify <fileToCheckSign> <pubKey> <signature>"
			 << endl << endl;
		return 1;
	}

	// Read file to be signed
	// sha256(sha256(z)) of messageFile to be signed
	string doubleSha = getHash(getHash(readFile(argv[2]),1),1);
	mpz_class z(doubleSha,16);
	GF message(z,secp256k1.N);

	// Sign the message using DER format
	if (string(argv[1]) == "sign")
	{
		// Create Private Key / Public Key
		string hex = decodeBase58(argv[3]);
		hex = remMainCheck(hex);
		GF privKey(mpz_class(hex,16),secp256k1.P);
		point pubKey = priv2pub(privKey);

		// Loop until finds a valid signature
		bool verify;
		GF R,S;
		do
		{
			do
			{
				// Create temporary private / public key
				GF sk    = genPriv();
				point pk = priv2pub(sk);

				// Create ECDSA signature
				// https://www.instructables.com/id/Understanding-how-ECDSA-protects-your-data/
				R = pk.x;
				S = ( message + GF(privKey.getNum(),secp256k1.N) 
					  * GF(R.getNum(),secp256k1.N) ) 
                      / GF(sk.getNum(),secp256k1.N);
			} while ( R == GF(0,secp256k1.P) or S == GF(0,secp256k1.N) );

			// Verify
			point p = add( 	priv2pub(message/S),
							priv2pub( GF(R.getNum(),secp256k1.N)/S, &pubKey) );
			if (p.x == R)
				verify = true;
			else
				verify = false;
		} while (!verify);

		// Create signature in DER format as hex string
		char buf[143];
		string strR, strS, strRS, der;

		// Convert R
		gmp_sprintf(buf,"%Z064x",R.getNum().get_mpz_t());
		strR = buf;
		if (strR[0] > '7')      // Add 00 if most significant bit is set
			strR = "00" + strR; // to avoid being interpreted as negative

		// Convert S
		gmp_sprintf(buf,"%Z064x",S.getNum().get_mpz_t());
		strS = buf;
		if (strS[0] > '7')
			strS = "00" + strS;

		// Concatenate R and S with their lengths
		sprintf(buf,"02%" PRIx64 "%s02%" PRIx64 "%s",
			strR.length()/2,
			strR.c_str(),
			strS.length()/2,
			strS.c_str());
		strRS = buf;

		// Conclude DER signature
		sprintf(buf,"30%" PRIx64 "%s",
			strRS.length()/2,
			strRS.c_str());
		der = buf;

		// Convert string sig to base64
		int length = der.length() / 2;
		uint8_t *source = new uint8_t[length];
		for (int i=0; i<(int)der.length(); i+=2)
			source[i/2] = stoul(der.substr(i,2),nullptr,16);
		string sigB64 = base64_encode(source,length);
		cout << "Signature = " << sigB64 << endl;
		delete [] source;
	}
	else
	{
		// Get remaining arguments
		string pubKey = argv[3];
		string sigB64 = argv[4];

		// Convert signature from base64 to hex string
		string sigBin = base64_decode(sigB64);
		string der = "";
		char buf[3];
		for (int i=0; i<(int)sigBin.length(); i++)
		{
			sprintf(buf,"%02hhx",sigBin[i]);
			der += buf;
		}

		// Get R and S from DER
		string strR, strS;
		int lenR, lenS;
		lenR = hex2int(der.substr(6,2));
		strR = der.substr(8,lenR*2);
		lenS = hex2int(der.substr(8+lenR*2+2,2));
		strS = der.substr(8+lenR*2+4,lenS*2);
		GF R(mpz_class(strR,16),secp256k1.P);
		GF S(mpz_class(strS,16),secp256k1.P);

		// Recover public key from signature
		// https://reinproject.org/static/bitcoin-signature-tool/js/bitcoinsig.js
		// https://github.com/nanotube/supybot-bitcoin-marketmonitor/blob/master/GPG/local/bitcoinsig.py
		bool found = false;
		for (int i=0; i<4; i++)
		{
			// Calculate public key from signature
			GF x = R + GF(secp256k1.N,secp256k1.P) * (i/2);
			GF alpha = x.pow(3) + 7;
			GF beta = alpha.pow((secp256k1.P+1)/4);
			GF y;
			if ( (beta-i)%2 == 0)
				y =  beta;
			else
				y = -beta;

			point r;
			r.x = x;
			r.y = y;
			point temp = add( priv2pub(S,&r) , priv2pub(-message) );
			point Q = priv2pub( GF(R.getNum(),secp256k1.N).pow(-1) , &temp );

			// Convert to base58check
			char pubBuf[131];
			gmp_sprintf(pubBuf, "04%Z064x%Z064x", Q.x.getNum().get_mpz_t(), Q.y.getNum().get_mpz_t());
			string pub  = binary2Addr(pubBuf);
			string pubC = binary2Addr(splitXY(pubBuf,Q));

			// Check if new addres equal the one given
			if (pub == pubKey || pubC == pubKey)
			{
				found = true;
				break;
			}
		}
		if (found)
		{
			cout << "Signature verification passed" << endl;
			return 0;
		}
		else
		{
			cout << "Signature verification failed" << endl;
			return 1;
		}
	}
}

