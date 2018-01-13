import java.util.Scanner;


public class AES_encryption {
	private static byte[] sBox = new byte[256];
	private static byte[] rsBox = new byte[256];
	private static byte[] E = new byte[256];
	private static byte[] L = new byte[256];
	private static byte[] rcon = new byte[256];
	private static byte[] eKey = new byte[176];
	private static int roundNumber;
	private static int messageLength;
	
	public static void loadRcon(){
		//load round constant table
		byte [] m = {
			    (byte)0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte)0x80, 0x1b, 0x36, 0x6c, (byte)0xd8, (byte)0xab, 0x4d, (byte)0x9a, 
			    0x2f, 0x5e, (byte)0xbc, 0x63, (byte)0xc6, (byte)0x97, 0x35, 0x6a, (byte)0xd4, (byte)0xb3, 0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5,(byte)0x91, 0x39, 
			    0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, 0x61, (byte)0xc2, (byte)0x9f, 0x25, 0x4a, (byte)0x94, 0x33, 0x66, (byte)0xcc, (byte)0x83, 0x1d, 0x3a, 
			    0x74, (byte)0xe8,(byte) 0xcb, (byte)0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte)0x80, 0x1b, 0x36, 0x6c, (byte)0xd8, 
			    (byte)0xab, 0x4d, (byte)0x9a, 0x2f, 0x5e, (byte)0xbc, 0x63, (byte)0xc6, (byte)0x97, 0x35, 0x6a, (byte)0xd4, (byte)0xb3, 0x7d,(byte) 0xfa, (byte)0xef, 
			    (byte)0xc5, (byte)0x91, 0x39, 0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, 0x61,(byte) 0xc2, (byte)0x9f, 0x25, 0x4a, (byte)0x94, 0x33, 0x66, (byte)0xcc, 
			    (byte) 0x83, 0x1d, 0x3a, 0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte)0x80, 0x1b, 
			    0x36, 0x6c, (byte)0xd8, (byte)0xab, 0x4d, (byte)0x9a, 0x2f, 0x5e, (byte)0xbc, 0x63, (byte)0xc6, (byte)0x97, 0x35, 0x6a, (byte)0xd4, (byte)0xb3, 
			    0x7d, (byte)0xfa,(byte) 0xef, (byte)0xc5, (byte)0x91, 0x39, 0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, 0x61, (byte)0xc2, (byte)0x9f, 0x25, 0x4a, (byte)0x94, 
			    0x33, 0x66, (byte)0xcc, (byte)0x83, 0x1d, 0x3a, 0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
			    0x40, (byte)0x80, 0x1b, 0x36, 0x6c,(byte) 0xd8, (byte)0xab, 0x4d, (byte)0x9a, 0x2f, 0x5e, (byte)0xbc, 0x63, (byte)0xc6, (byte)0x97, 0x35, 
			    0x6a, (byte)0xd4, (byte)0xb3, 0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, 0x39, 0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, 0x61, (byte)0xc2, (byte)0x9f, 
			    0x25, 0x4a, (byte)0x94, 0x33, 0x66,(byte)0xcc, (byte)0x83, 0x1d, 0x3a, 0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d, 0x01, 0x02, 0x04, 
			    0x08, 0x10, 0x20, 0x40, (byte)0x80, 0x1b, 0x36, 0x6c, (byte)0xd8, (byte)0xab, 0x4d, (byte)0x9a, 0x2f, 0x5e, (byte)0xbc, 0x63, 
			    (byte)0xc6, (byte)0x97, 0x35, 0x6a, (byte)0xd4, (byte)0xb3, 0x7d, (byte)0xfa, (byte)0xef, (byte)0xc5, (byte)0x91, 0x39, 0x72, (byte)0xe4, (byte)0xd3, (byte)0xbd, 
			    0x61, (byte)0xc2, (byte)0x9f, 0x25, 0x4a, (byte)0x94, 0x33, 0x66, (byte)0xcc, (byte)0x83, 0x1d, 0x3a, 0x74, (byte)0xe8, (byte)0xcb, (byte)0x8d
			};
		rcon = m;
	}
	public static void loadL(){
		//load L table
		byte [] m = { (byte)0x00 ,(byte)0x00 ,(byte)0x19 ,(byte)0x01 ,(byte)0x32 ,(byte)0x02 ,(byte)0x1A ,(byte)0xC6 ,(byte)0x4B ,(byte)0xC7 ,(byte)0x1B ,(byte)0x68 ,(byte)0x33 ,(byte)0xEE ,(byte)0xDF ,(byte)0x03,
				(byte)0x64 ,(byte)0x04 ,(byte)0xE0 ,(byte)0x0E ,(byte)0x34 ,(byte)0x8D ,(byte)0x81 ,(byte)0xEF ,(byte)0x4C ,(byte)0x71 ,(byte)0x08 ,(byte)0xC8 ,(byte)0xF8 ,(byte)0x69 ,(byte)0x1C ,(byte)0xC1,
				(byte)0x7D ,(byte)0xC2 ,(byte)0x1D ,(byte)0xB5 ,(byte)0xF9 ,(byte)0xB9 ,(byte)0x27 ,(byte)0x6A ,(byte)0x4D ,(byte)0xE4 ,(byte)0xA6 ,(byte)0x72 ,(byte)0x9A ,(byte)0xC9 ,(byte)0x09 ,(byte)0x78,
				(byte)0x65 ,(byte)0x2F ,(byte)0x8A ,(byte)0x05 ,(byte)0x21 ,(byte)0x0F ,(byte)0xE1 ,(byte)0x24 ,(byte)0x12 ,(byte)0xF0 ,(byte)0x82 ,(byte)0x45 ,(byte)0x35 ,(byte)0x93 ,(byte)0xDA ,(byte)0x8E,
				(byte)0x96 ,(byte)0x8F ,(byte)0xDB ,(byte)0xBD ,(byte)0x36 ,(byte)0xD0 ,(byte)0xCE ,(byte)0x94 ,(byte)0x13 ,(byte)0x5C ,(byte)0xD2 ,(byte)0xF1 ,(byte)0x40 ,(byte)0x46 ,(byte)0x83 ,(byte)0x38,
				(byte)0x66 ,(byte)0xDD ,(byte)0xFD ,(byte)0x30 ,(byte)0xBF ,(byte)0x06 ,(byte)0x8B ,(byte)0x62 ,(byte)0xB3 ,(byte)0x25 ,(byte)0xE2 ,(byte)0x98 ,(byte)0x22 ,(byte)0x88 ,(byte)0x91 ,(byte)0x10,
				(byte)0x7E ,(byte)0x6E ,(byte)0x48 ,(byte)0xC3 ,(byte)0xA3 ,(byte)0xB6 ,(byte)0x1E ,(byte)0x42 ,(byte)0x3A ,(byte)0x6B ,(byte)0x28 ,(byte)0x54 ,(byte)0xFA ,(byte)0x85 ,(byte)0x3D ,(byte)0xBA,
				(byte)0x2B ,(byte)0x79 ,(byte)0x0A ,(byte)0x15 ,(byte)0x9B ,(byte)0x9F ,(byte)0x5E ,(byte)0xCA ,(byte)0x4E ,(byte)0xD4 ,(byte)0xAC ,(byte)0xE5 ,(byte)0xF3 ,(byte)0x73 ,(byte)0xA7 ,(byte)0x57,
				(byte)0xAF ,(byte)0x58 ,(byte)0xA8 ,(byte)0x50 ,(byte)0xF4 ,(byte)0xEA ,(byte)0xD6 ,(byte)0x74 ,(byte)0x4F ,(byte)0xAE ,(byte)0xE9 ,(byte)0xD5 ,(byte)0xE7 ,(byte)0xE6 ,(byte)0xAD ,(byte)0xE8,
				(byte)0x2C ,(byte)0xD7 ,(byte)0x75 ,(byte)0x7A ,(byte)0xEB ,(byte)0x16 ,(byte)0x0B ,(byte)0xF5 ,(byte)0x59 ,(byte)0xCB ,(byte)0x5F ,(byte)0xB0 ,(byte)0x9C ,(byte)0xA9 ,(byte)0x51 ,(byte)0xA0,
				(byte)0x7F ,(byte)0x0C ,(byte)0xF6 ,(byte)0x6F ,(byte)0x17 ,(byte)0xC4 ,(byte)0x49 ,(byte)0xEC ,(byte)0xD8 ,(byte)0x43 ,(byte)0x1F ,(byte)0x2D ,(byte)0xA4 ,(byte)0x76 ,(byte)0x7B ,(byte)0xB7,
				(byte)0xCC ,(byte)0xBB ,(byte)0x3E ,(byte)0x5A ,(byte)0xFB ,(byte)0x60 ,(byte)0xB1 ,(byte)0x86 ,(byte)0x3B ,(byte)0x52 ,(byte)0xA1 ,(byte)0x6C ,(byte)0xAA ,(byte)0x55 ,(byte)0x29 ,(byte)0x9D,
				(byte)0x97 ,(byte)0xB2 ,(byte)0x87 ,(byte)0x90 ,(byte)0x61 ,(byte)0xBE ,(byte)0xDC ,(byte)0xFC ,(byte)0xBC ,(byte)0x95 ,(byte)0xCF ,(byte)0xCD ,(byte)0x37 ,(byte)0x3F ,(byte)0x5B ,(byte)0xD1,
				(byte)0x53 ,(byte)0x39 ,(byte)0x84 ,(byte)0x3C ,(byte)0x41 ,(byte)0xA2 ,(byte)0x6D ,(byte)0x47 ,(byte)0x14 ,(byte)0x2A ,(byte)0x9E ,(byte)0x5D ,(byte)0x56 ,(byte)0xF2 ,(byte)0xD3,(byte)0xAB,
				(byte)0x44 ,(byte)0x11 ,(byte)0x92 ,(byte)0xD9 ,(byte)0x23 ,(byte)0x20 ,(byte)0x2E,(byte)0x89 ,(byte)0xB4 ,(byte)0x7C ,(byte)0xB8 ,(byte)0x26 ,(byte)0x77 ,(byte)0x99 ,(byte)0xE3 ,(byte)0xA5,
				(byte)0x67 ,(byte)0x4A ,(byte)0xED ,(byte)0xDE ,(byte)0xC5 ,(byte)0x31 ,(byte)0xFE ,(byte)0x18 ,(byte)0x0D ,(byte)0x63 ,(byte)0x8C ,(byte)0x80 ,(byte)0xC0 ,(byte)0xF7 ,(byte)0x70 ,(byte)0x07};
		L = m;
	}
	public static void loadE(){
		//load E table
		byte [] m = {0x01, 0x03, 0x05, (byte)0x0F, 0x11, 0x33, 0x55, (byte)0xFF, (byte)0x1A,(byte)0x2E, 0x72, (byte)0x96, (byte)0xA1,(byte) 0xF8, 0x13, 0x35,
				(byte)0x5F ,(byte)0xE1, (byte)0x38 ,(byte)0x48, (byte)0xD8, (byte)0x73 ,(byte)0x95, (byte)0xA4, (byte)0xF7, (byte)0x02, (byte)0x06, (byte)0x0A, (byte)0x1E, (byte)0x22, (byte)0x66, (byte)0xAA,
				(byte)0xE5 ,(byte)0x34 ,(byte)0x5C ,(byte)0xE4 ,(byte)0x37 ,(byte)0x59 ,(byte)0xEB ,(byte)0x26 ,(byte)0x6A ,(byte)0xBE ,(byte)0xD9 ,(byte)0x70 ,(byte)0x90 ,(byte)0xAB ,(byte)0xE6 ,(byte)0x31,
				(byte)0x53 ,(byte)0xF5 ,(byte)0x04 ,(byte)0x0C ,(byte)0x14 ,(byte)0x3C ,(byte)0x44 ,(byte)0xCC ,(byte)0x4F ,(byte)0xD1 ,(byte)0x68 ,(byte)0xB8 ,(byte)0xD3 ,(byte)0x6E ,(byte)0xB2 ,(byte)0xCD,
				(byte)0x4C ,(byte)0xD4 ,(byte)0x67 ,(byte)0xA9 ,(byte)0xE0 ,(byte)0x3B ,(byte)0x4D ,(byte)0xD7 ,(byte)0x62 ,(byte)0xA6 ,(byte)0xF1 ,(byte)0x08 ,(byte)0x18 ,(byte)0x28 ,(byte)0x78 ,(byte)0x88,
				(byte)0x83 ,(byte)0x9E ,(byte)0xB9 ,(byte)0xD0 ,(byte)0x6B ,(byte)0xBD ,(byte)0xDC ,(byte)0x7F ,(byte)0x81 ,(byte)0x98 ,(byte)0xB3 ,(byte)0xCE ,(byte)0x49 ,(byte)0xDB ,(byte)0x76 ,(byte)0x9A,
				(byte)0xB5 ,(byte)0xC4 ,(byte)0x57 ,(byte)0xF9 ,(byte)0x10 ,(byte)0x30 ,(byte)0x50 ,(byte)0xF0 ,(byte)0x0B ,(byte)0x1D ,(byte)0x27 ,(byte)0x69 ,(byte)0xBB ,(byte)0xD6 ,(byte)0x61 ,(byte)0xA3,
				(byte)0xFE ,(byte)0x19 ,(byte)0x2B ,(byte)0x7D ,(byte)0x87 ,(byte)0x92 ,(byte)0xAD ,(byte)0xEC ,(byte)0x2F ,(byte)0x71 ,(byte)0x93 ,(byte)0xAE ,(byte)0xE9 ,(byte)0x20 ,(byte)0x60 ,(byte)0xA0,
				(byte)0xFB ,(byte)0x16 ,(byte)0x3A ,(byte)0x4E ,(byte)0xD2 ,(byte)0x6D ,(byte)0xB7 ,(byte)0xC2 ,(byte)0x5D ,(byte)0xE7 ,(byte)0x32 ,(byte)0x56 ,(byte)0xFA ,(byte)0x15 ,(byte)0x3F ,(byte)0x41,
				(byte)0xC3 ,(byte)0x5E ,(byte)0xE2 ,(byte)0x3D ,(byte)0x47 ,(byte)0xC9 ,(byte)0x40 ,(byte)0xC0 ,(byte)0x5B ,(byte)0xED ,(byte)0x2C ,(byte)0x74 ,(byte)0x9C ,(byte)0xBF ,(byte)0xDA ,(byte)0x75,
				(byte)0x9F ,(byte)0xBA ,(byte)0xD5 ,(byte)0x64 ,(byte)0xAC ,(byte)0xEF ,(byte)0x2A ,(byte)0x7E ,(byte)0x82 ,(byte)0x9D ,(byte)0xBC ,(byte)0xDF ,(byte)0x7A ,(byte)0x8E ,(byte)0x89 ,(byte)0x80,
				(byte)0x9B ,(byte)0xB6 ,(byte)0xC1 ,(byte)0x58 ,(byte)0xE8 ,(byte)0x23 ,(byte)0x65 ,(byte)0xAF ,(byte)0xEA ,(byte)0x25 ,(byte)0x6F ,(byte)0xB1 ,(byte)0xC8 ,(byte)0x43 ,(byte)0xC5 ,(byte)0x54,
				(byte)0xFC ,(byte)0x1F ,(byte)0x21 ,(byte)0x63 ,(byte)0xA5 ,(byte)0xF4 ,(byte)0x07 ,(byte)0x09 ,(byte)0x1B ,(byte)0x2D ,(byte)0x77 ,(byte)0x99 ,(byte)0xB0 ,(byte)0xCB ,(byte)0x46 ,(byte)0xCA,
				(byte)0x45 ,(byte)0xCF ,(byte)0x4A ,(byte)0xDE ,(byte)0x79,(byte)0x8B ,(byte)0x86 ,(byte)0x91 ,(byte)0xA8 ,(byte)0xE3 ,(byte)0x3E ,(byte)0x42 ,(byte)0xC6 ,(byte)0x51 ,(byte)0xF3 ,(byte)0x0E,
				(byte)0x12 ,(byte)0x36 ,(byte)0x5A ,(byte)0xEE ,(byte)0x29 ,(byte)0x7B ,(byte)0x8D ,(byte)0x8C ,(byte)0x8F ,(byte)0x8A ,(byte)0x85 ,(byte)0x94 ,(byte)0xA7 ,(byte)0xF2 ,(byte)0x0D ,(byte)0x17,
				(byte)0x39 ,(byte)0x4B ,(byte)0xDD ,(byte)0x7C ,(byte)0x84 ,(byte)0x97 ,(byte)0xA2 ,(byte)0xFD ,(byte)0x1C ,(byte)0x24 ,(byte)0x6C ,(byte)0xB4 ,(byte)0xC7 ,(byte)0x52 ,(byte)0xF6 ,(byte)0x01};
		E = m;
	}
	public static void loadEK(byte [] key){
		//put 16 bit key in first 16 slots of eKey
		for(int i = 0; i < 16; i++){
			eKey[i] = key[i];
		}
		int i = 16; //takes in account of already filled 16 slots
		int j = 1; //to get correct round constant
		while(i < eKey.length){
			//get last four bytes from previous round key
			byte[] k = {eKey[i-4],eKey[i-3],eKey[i-2],eKey[i-1]}; 
			k = byteSub(lShift(k)); //left shift and byte substitue
			byte [] rc = {rcon[j],0,0,0}; //get correct array for round constant
			j++;
			/*first word //last four bytes from previous round xor-ed with round constant 
			xor-ed with first four bytes from previous round*/
			eKey[i] = (byte) (k[0] ^ rc[0] ^ eKey[i-16]);
			eKey[i+1] = (byte)(k[1]^rc[1] ^ eKey[i-15]);
			eKey[i+2] = (byte)(k[2]^rc[2] ^ eKey[i-14]);
			eKey[i+3] = (byte)(k[3]^rc[3] ^ eKey[i-13]);
			//second word
			eKey[i+4] = (byte)(eKey[i]^eKey[i-12]);
			eKey[i+5] = (byte)(eKey[i+1]^eKey[i-11]);
			eKey[i+6] = (byte)(eKey[i+2]^eKey[i-10]);
			eKey[i+7] = (byte)(eKey[i+3]^eKey[i-9]);
			//third word
			eKey[i+8] = (byte)(eKey[i+4]^eKey[i-8]);
			eKey[i+9] = (byte)(eKey[i+5]^eKey[i-7]);
			eKey[i+10] = (byte)(eKey[i+6]^eKey[i-6]);
			eKey[i+11] = (byte)(eKey[i+7]^eKey[i-5]);
			//fourth word
			eKey[i+12] = (byte)(eKey[i+8]^eKey[i-4]);
			eKey[i+13] = (byte)(eKey[i+9]^eKey[i-3]);
			eKey[i+14] = (byte)(eKey[i+10]^eKey[i-2]);
			eKey[i+15] = (byte)(eKey[i+11]^eKey[i-1]);
			i +=16;
		}
	}
	public static void sbox(){
		//create Sbox
		//GF(2^8) = GF(2)[x]/(x^8 + x^4 + x^3 + x + 1)
		byte sB[] = 
			 {
				(byte)0x63 ,(byte)0x7C ,(byte)0x77 ,(byte)0x7B ,(byte)0xF2 ,(byte)0x6B ,(byte)0x6F ,(byte)0xC5 ,(byte)0x30 ,(byte)0x01 ,(byte)0x67 ,(byte)0x2B ,(byte)0xFE ,(byte)0xD7 ,(byte)0xAB ,(byte)0x76,
				(byte)0xCA ,(byte)0x82 ,(byte)0xC9 ,(byte)0x7D ,(byte)0xFA ,(byte)0x59 ,(byte)0x47 ,(byte)0xF0 ,(byte)0xAD ,(byte)0xD4 ,(byte)0xA2 ,(byte)0xAF ,(byte)0x9C ,(byte)0xA4 ,(byte)0x72 ,(byte)0xC0,
				(byte)0xB7 ,(byte)0xFD ,(byte)0x93 ,(byte)0x26 ,(byte)0x36 ,(byte)0x3F ,(byte)0xF7 ,(byte)0xCC ,(byte)0x34 ,(byte)0xA5 ,(byte)0xE5 ,(byte)0xF1 ,(byte)0x71 ,(byte)0xD8 ,(byte)0x31 ,(byte)0x15,
				(byte)0x04 ,(byte)0xC7 ,(byte)0x23 ,(byte)0xC3 ,(byte)0x18 ,(byte)0x96 ,(byte)0x05 ,(byte)0x9A ,(byte)0x07 ,(byte)0x12 ,(byte)0x80 ,(byte)0xE2 ,(byte)0xEB ,(byte)0x27 ,(byte)0xB2 ,(byte)0x75,
				(byte)0x09 ,(byte)0x83 ,(byte)0x2C ,(byte)0x1A ,(byte)0x1B ,(byte)0x6E ,(byte)0x5A ,(byte)0xA0 ,(byte)0x52 ,(byte)0x3B ,(byte)0xD6 ,(byte)0xB3 ,(byte)0x29 ,(byte)0xE3 ,(byte)0x2F ,(byte)0x84,
				(byte)0x53 ,(byte)0xD1 ,(byte)0x00 ,(byte)0xED ,(byte)0x20 ,(byte)0xFC ,(byte)0xB1 ,(byte)0x5B ,(byte)0x6A ,(byte)0xCB ,(byte)0xBE ,(byte)0x39 ,(byte)0x4A ,(byte)0x4C ,(byte)0x58 ,(byte)0xCF,
				(byte)0xD0 ,(byte)0xEF ,(byte)0xAA ,(byte)0xFB ,(byte)0x43 ,(byte)0x4D ,(byte)0x33 ,(byte)0x85 ,(byte)0x45 ,(byte)0xF9 ,(byte)0x02 ,(byte)0x7F ,(byte)0x50 ,(byte)0x3C, (byte)0x9F ,(byte)0xA8,
				(byte)0x51 ,(byte)0xA3 ,(byte)0x40 ,(byte)0x8F ,(byte)0x92 ,(byte)0x9D ,(byte)0x38 ,(byte)0xF5 ,(byte)0xBC ,(byte)0xB6 ,(byte)0xDA ,(byte)0x21 ,(byte)0x10 ,(byte)0xFF ,(byte)0xF3 ,(byte)0xD2,
				(byte)0xCD ,(byte)0x0C ,(byte)0x13 ,(byte)0xEC ,(byte)0x5F ,(byte)0x97 ,(byte)0x44 ,(byte)0x17 ,(byte)0xC4 ,(byte)0xA7 ,(byte)0x7E ,(byte)0x3D ,(byte)0x64 ,(byte)0x5D ,(byte)0x19 ,(byte)0x73,
				(byte)0x60 ,(byte)0x81 ,(byte)0x4F ,(byte)0xDC ,(byte)0x22 ,(byte)0x2A ,(byte)0x90 ,(byte)0x88 ,(byte)0x46 ,(byte)0xEE ,(byte)0xB8 ,(byte)0x14 ,(byte)0xDE ,(byte)0x5E ,(byte)0x0B ,(byte)0xDB,
				(byte)0xE0 ,(byte)0x32 ,(byte)0x3A ,(byte)0x0A ,(byte)0x49 ,(byte)0x06 ,(byte)0x24 ,(byte)0x5C ,(byte)0xC2 ,(byte)0xD3 ,(byte)0xAC ,(byte)0x62 ,(byte)0x91 ,(byte)0x95 ,(byte)0xE4 ,(byte)0x79,
				(byte)0xE7 ,(byte)0xC8 ,(byte)0x37 ,(byte)0x6D ,(byte)0x8D ,(byte)0xD5 ,(byte)0x4E ,(byte)0xA9 ,(byte)0x6C ,(byte)0x56 ,(byte)0xF4 ,(byte)0xEA ,(byte)0x65 ,(byte)0x7A ,(byte)0xAE ,(byte)0x08,
				(byte)0xBA ,(byte)0x78 ,(byte)0x25 ,(byte)0x2E ,(byte)0x1C ,(byte)0xA6 ,(byte)0xB4 ,(byte)0xC6 ,(byte)0xE8 ,(byte)0xDD ,(byte)0x74 ,(byte)0x1F ,(byte)0x4B ,(byte)0xBD ,(byte)0x8B ,(byte)0x8A,
				(byte)0x70 ,(byte)0x3E ,(byte)0xB5 ,(byte)0x66 ,(byte)0x48 ,(byte)0x03 ,(byte)0xF6 ,(byte)0x0E ,(byte)0x61 ,(byte)0x35 ,(byte)0x57 ,(byte)0xB9 ,(byte)0x86 ,(byte)0xC1 ,(byte)0x1D ,(byte)0x9E,
				(byte)0xE1 ,(byte)0xF8 ,(byte)0x98 ,(byte)0x11 ,(byte)0x69 ,(byte)0xD9 ,(byte)0x8E ,(byte)0x94 ,(byte)0x9B ,(byte)0x1E ,(byte)0x87 ,(byte)0xE9 ,(byte)0xCE ,(byte)0x55 ,(byte)0x28 ,(byte)0xDF,
				(byte)0x8C ,(byte)0xA1 ,(byte)0x89 ,(byte)0x0D ,(byte)0xBF ,(byte)0xE6 ,(byte)0x42 ,(byte)0x68 ,(byte)0x41 ,(byte)0x99 ,(byte)0x2D ,(byte)0x0F ,(byte)0xB0 ,(byte)0x54 ,(byte)0xBB ,(byte)0x16
			 };
		sBox = sB;
	}
	public static void rsbox(){
		//create rSbox
		//GF(2^8) = GF(2)[x]/(x^8 + x^4 + x^3 + x + 1)
		byte inv_s[] = 
			 {
			    0x52, 0x09, 0x6A, (byte)0xD5, 0x30, 0x36, (byte)0xA5, 0x38, (byte)0xBF, 0x40, (byte)0xA3, (byte)0x9E, (byte)0x81, (byte)0xF3,(byte) 0xD7, (byte)0xFB,
			    0x7C, (byte)0xE3, 0x39, (byte)0x82, (byte)0x9B, 0x2F, (byte)0xFF, (byte)0x87, 0x34, (byte)0x8E, 0x43, 0x44, (byte)0xC4, (byte)0xDE, (byte)0xE9, (byte)0xCB,
			    0x54, 0x7B, (byte)0x94, 0x32, (byte)0xA6, (byte)0xC2, 0x23, 0x3D, (byte)0xEE, 0x4C, (byte)0x95, 0x0B, 0x42, (byte)0xFA, (byte)0xC3, 0x4E,
			    0x08, 0x2E, (byte)0xA1, 0x66, 0x28, (byte)0xD9, 0x24,(byte) 0xB2, 0x76, 0x5B, (byte)0xA2, 0x49, 0x6D, (byte)0x8B, (byte)0xD1, 0x25,
			    0x72, (byte)0xF8, (byte)0xF6, 0x64, (byte)0x86, 0x68, (byte)0x98, 0x16, (byte)0xD4, (byte)0xA4, 0x5C, (byte)0xCC, 0x5D, 0x65, (byte)0xB6, (byte)0x92,
			    0x6C, 0x70, 0x48, 0x50, (byte)0xFD, (byte)0xED, (byte)0xB9, (byte)0xDA, 0x5E, 0x15, 0x46, 0x57, (byte)0xA7, (byte)0x8D, (byte)0x9D,(byte) 0x84,
			    (byte)0x90, (byte)0xD8, (byte)0xAB, 0x00, (byte)0x8C, (byte)0xBC, (byte)0xD3, 0x0A, (byte)0xF7, (byte)0xE4, 0x58, 0x05, (byte)0xB8, (byte)0xB3, 0x45, 0x06,
			    (byte)0xD0, 0x2C, 0x1E, (byte)0x8F, (byte)0xCA, 0x3F, 0x0F, 0x02, (byte)0xC1, (byte)0xAF, (byte)0xBD, 0x03, 0x01, 0x13, (byte)0x8A, 0x6B,
			    0x3A, (byte)0x91, 0x11, 0x41, 0x4F, 0x67, (byte)0xDC, (byte)0xEA, (byte)0x97, (byte)0xF2, (byte)0xCF, (byte)0xCE, (byte)0xF0, (byte)0xB4, (byte)0xE6, 0x73,
			    (byte)0x96, (byte)0xAC, 0x74, 0x22, (byte)0xE7, (byte)0xAD, 0x35, (byte)0x85, (byte)0xE2, (byte)0xF9, 0x37, (byte)0xE8, 0x1C, 0x75, (byte)0xDF, 0x6E,
			    0x47, (byte)0xF1, 0x1A, 0x71, 0x1D, 0x29, (byte)0xC5, (byte)0x89, 0x6F, (byte)0xB7, 0x62, 0x0E, (byte)0xAA, 0x18, (byte)0xBE, 0x1B,
			    (byte)0xFC, 0x56, 0x3E, 0x4B, (byte)0xC6, (byte)0xD2, 0x79, 0x20, (byte)0x9A, (byte)0xDB, (byte)0xC0, (byte)0xFE, 0x78, (byte)0xCD, 0x5A, (byte)0xF4,
			    0x1F, (byte)0xDD, (byte)0xA8, 0x33, (byte)0x88, 0x07, (byte)0xC7, 0x31, (byte)0xB1, 0x12, 0x10, 0x59, 0x27, (byte)0x80, (byte)0xEC, 0x5F,
			    0x60, 0x51, 0x7F, (byte)0xA9, 0x19, (byte)0xB5, 0x4A, 0x0D, 0x2D, (byte)0xE5, 0x7A, (byte)0x9F, (byte)0x93, (byte)0xC9, (byte)0x9C,(byte) 0xEF,
			    (byte)0xA0, (byte)0xE0, 0x3B, 0x4D, (byte)0xAE, 0x2A, (byte)0xF5, (byte)0xB0, (byte)0xC8, (byte)0xEB, (byte)0xBB, 0x3C, (byte)0x83, 0x53,(byte) 0x99, 0x61,
			    0x17, 0x2B, 0x04, 0x7E, (byte)0xBA, 0x77, (byte)0xD6, 0x26, (byte)0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
			 };
		rsBox = inv_s;
	}
	public static byte[] rByteSub(byte[] state){
		//goes through every element of state block and swaps it with its correct value from the rSbox to get original value
		for(int i = 0; i < state.length; i++){
			state[i] = (byte) (0xff&rsBox[0xff&state[i]]);
		}
		return state;
	}
	public static byte[] byteSub(byte[] state){
		//goes through every element of state block and swaps it with its correct value from the Sbox
		for(int i = 0; i < state.length; i++){
	    	state[i] = (byte) (0xff&sBox[0xff&state[i]]);
		}
		return state;
	}
	public static byte[] lShift(byte[] x){
		//swaps arrays
		byte r = x[0];
		x[0] = x[1];
		x[1] = x[2];
		x[2] = x[3];
		x[3] = r;
		return x;
	}
	public static byte[] shiftLeft(byte[] state){
		// 1 5 9 13   stays the same
		// 2 6 10 14  shift left once
		// 3 7 11 15  shift left twice
		// 4 8 12 16  shift left thrice
		int a = 0, b = 4, c=8, d=12;
		byte[] row1 = {state[a],state[b],state[c],state[d]};
		byte[] row2 = {state[a+1],state[b+1],state[c+1],state[d+1]};
		row2 = lShift(row2);
		byte[] row3 = {state[a+2],state[b+2],state[c+2],state[d+2]};
		row3 = lShift(lShift(row3));
		byte[] row4 = {state[a+3],state[b+3],state[c+3],state[d+3]};
		row4 = lShift(lShift(lShift(row4)));
		int j = 0;
		//put new rows into state slots
		for(int i = 0; i < 4; i++){
			state[j] = row1[i];
			state[j+1] = row2[i];
			state[j+2] = row3[i];
			state[j+3] = row4[i];
			j+=4;
		}
		return state;
	}
	public static byte[] rShift(byte[] x){
		//swap elements in array
		byte r = x[3];
		x[3] = x[2];
		x[2] = x[1];
		x[1] = x[0];
		x[0] = r;
		return x;
	}
	public static byte[] shiftRight(byte[] state){
		// 1 5 9 13    leave the same
		// 2 6 10 14   right shift once
		// 3 7 11 15   right shift twice
		// 4 8 12 16   right shift thrice
		int a = 0, b = 4, c=8, d=12; //get start column
		byte[] row1 = {state[a],state[b],state[c],state[d]};
		byte[] row2 = {state[a+1],state[b+1],state[c+1],state[d+1]};
		row2 = rShift(row2);
		byte[] row3 = {state[a+2],state[b+2],state[c+2],state[d+2]};
		row3 = rShift(rShift(row3));
		byte[] row4 = {state[a+3],state[b+3],state[c+3],state[d+3]};
		row4 = rShift(rShift(rShift(row4)));		
		int j = 0;
		//put new rows into state slots
		for(int i = 0; i < 4; i++){
			state[j] = row1[i];
			state[j+1] = row2[i];
			state[j+2] = row3[i];
			state[j+3] = row4[i];
			j+=4;
		}
		return state;
	}
	public static byte math(byte a, byte b, byte c, byte d, byte [] mm){
		byte [] temp = new byte [4]; //create array to hold byte value to xor later.
		//s holds the bytes from paramators. & with 0xff to make it positive... since java doesnt have unsigned
		byte [] s = {(byte)(0xff&a),(byte)(0xff&b),(byte)(0xff&c),(byte)(0xff&d)}; 
		for(int i = 0; i < 4; i++){
			//x and y grab values from Log table
			byte x = L[0xff&s[i]], y = L[0xff&mm[i]];
			//decide how x and y should be calculated
			if((0xff&mm[i]) == (byte)1){
				temp[i] = (byte)(0xff&s[i]);
				//System.out.println("temp[" +i+"]:" + (0xff&temp[i]));
			}
			else if((0xff&mm[i]) == (byte)0 || (0xff&s[i]) == (byte)0){
				temp[i] = 0;
			}
			else if(((0xff&x) +(0xff&y)) > 255){
				temp[i] = E[(((0xff&x) + (0xff&y)) - 0xff)];
			}
			else{
				temp[i] = E[(0xff&(x+y))];
			}	
		}
		//xors all values from temp together
		return (byte) ((0xff&temp[0])^(0xff&temp[1])^(0xff&temp[2])^(0xff&temp[3]));
	}
	public static byte[] multMatrix(byte [] state){
		byte [] mm = {(byte)2,(byte)3,(byte)1,(byte)1};// create row (matrix) to matrix multiply with
		byte [] bs = new byte [16]; //create new array to hold bytes from matrix multiplication
		bs[0] = math(state[0],state[1],state[2],state[3], mm);
		mm = rShift(mm);// 1 2 3 1 
		bs[1] = math(state[0],state[1],state[2],state[3], mm);
		mm = rShift(mm); // 1 1 2 3
		bs[2] = math(state[0],state[1],state[2],state[3], mm);
		mm = rShift(mm); // 3 1 1 2
		bs[3] = math(state[0],state[1],state[2],state[3], mm);
		mm = rShift(mm); //reset // 2 3 1 1
		bs[4] = math(state[4],state[5],state[6],state[7], mm);
		mm = rShift(mm);// 1 2 3 1 
		bs[5] = math(state[4],state[5],state[6],state[7], mm);
		mm = rShift(mm);// 1 1 2 3
		bs[6] = math(state[4],state[5],state[6],state[7], mm);
		mm = rShift(mm); // 3 1 1 2
		bs[7] = math(state[4],state[5],state[6],state[7], mm);
		mm = rShift(mm); //reset // 2 3 1 1
		bs[8] = math(state[8],state[9],state[10],state[11], mm);
		mm = rShift(mm); // 1 2 3 1 
		bs[9] = math(state[8],state[9],state[10],state[11], mm);
		mm = rShift(mm);// 1 1 2 3
		bs[10] = math(state[8],state[9],state[10],state[11], mm);
		mm = rShift(mm);// 3 1 1 2
		bs[11] = math(state[8],state[9],state[10],state[11], mm);
		mm = rShift(mm); //reset // 2 3 1 1
		bs[12] = math(state[12],state[13],state[14],state[15], mm);
		mm = rShift(mm);// 1 2 3 1 
		bs[13] = math(state[12],state[13],state[14],state[15], mm);
		mm = rShift(mm);// 1 1 2 3
		bs[14] = math(state[12],state[13],state[14],state[15], mm);
		mm = rShift(mm);// 3 1 1 2
		bs[15] = math(state[12],state[13],state[14],state[15], mm);
		
		return bs;
	}
	public static byte[] inverseMultMatrix(byte [] state){
		//create new matrix to hold bytes of matrix multiplication
		byte [] bs = new byte [16];
		byte [] mm = {(byte)14,(byte)11,(byte)13,(byte)9}; //create row (matrix) to matrix multiply with
		bs[0] = math(state[0],state[1],state[2],state[3], mm);
		mm = rShift(mm);// 9 14 11 13 
		bs[1] = math(state[0],state[1],state[2],state[3], mm);
		mm = rShift(mm); // 13 9 14 11
		bs[2] = math(state[0],state[1],state[2],state[3], mm);
		mm = rShift(mm); // 11 13 9 14
		bs[3] = math(state[0],state[1],state[2],state[3], mm);
		mm = rShift(mm); //reset // 14 11 13 9
		bs[4] = math(state[4],state[5],state[6],state[7], mm);
		mm = rShift(mm);// 9 14 11 13
		bs[5] = math(state[4],state[5],state[6],state[7], mm);
		mm = rShift(mm);// 13 9 14 11
		bs[6] = math(state[4],state[5],state[6],state[7], mm);
		mm = rShift(mm); // 11 13 9 14
		bs[7] = math(state[4],state[5],state[6],state[7], mm);
		mm = rShift(mm); //reset // 14 11 13 9
		bs[8] = math(state[8],state[9],state[10],state[11], mm);
		mm = rShift(mm); // 9 14 11 13 
		bs[9] = math(state[8],state[9],state[10],state[11], mm);
		mm = rShift(mm);// 13 9 14 11
		bs[10] = math(state[8],state[9],state[10],state[11], mm);
		mm = rShift(mm);// 11 13 9 14
		bs[11] = math(state[8],state[9],state[10],state[11], mm);
		mm = rShift(mm); //reset // 14 11 13 9
		bs[12] = math(state[12],state[13],state[14],state[15], mm);
		mm = rShift(mm);// 9 14 11 13
		bs[13] = math(state[12],state[13],state[14],state[15], mm);
		mm = rShift(mm);// 13 9 14 11
		bs[14] = math(state[12],state[13],state[14],state[15], mm);
		mm = rShift(mm);// 11 13 9 14
		bs[15] = math(state[12],state[13],state[14],state[15], mm);
		return bs;
	}
	public static byte[] addRoundKey(byte [] state){
		//add round key
		for(int i = 0; i < 16; i++){
			state[i] = (byte) ((0xff&state[i]) ^ eKey[roundNumber+i]);
		}
		roundNumber+=16; //points now to the next start of the block
		return state;
	}
	public static byte[] iaddRoundKey(byte [] state){
		//adds round key starting at back of array
		roundNumber-=16; //points to the start of the block for roundkey
		for(int i = 0; i <16; i++){
			state[i] = (byte) ((0xff&state[i]) ^ eKey[roundNumber+i]);
		}
		return state;
	}
	public static byte[] encrypt(byte[] state){
		//encyption process
		state = addRoundKey(state);
		for(int i = 0; i < 9; i++){
			state = addRoundKey(multMatrix(shiftLeft(byteSub(state))));
		}
		return addRoundKey(shiftLeft(byteSub(state)));
	}
	public static void print(byte[] x){
		//prints char of array
		for(int j = 0; j < messageLength; j++){
			System.out.print((char)(0xff&x[j]));
		}
		System.out.println();
		//prints hex value of array
		for(int j = 0; j < messageLength; j++){
			System.out.print(Integer.toHexString(0xff&x[j]));
		}
		System.out.println();
	}
	public static byte[] decrypt(byte[] state) {
		//decrypt proccess
		state = iaddRoundKey(state);
		for(int i = 0; i < 9; i++){
			state = inverseMultMatrix(iaddRoundKey(rByteSub(shiftRight(state))));
		}
		return iaddRoundKey(rByteSub(shiftRight(state)));		
	}
	public static void main(String[] args) {
		
		//initialize boxes
		sbox();
		rsbox(); 
		loadE();
		loadL();
		loadRcon();
		
		System.out.println("first test:");
		byte[] state = {(byte)0x32,(byte)0x43 ,(byte)0xf6 ,(byte)0xa8 ,(byte)0x88 ,(byte)0x5a ,(byte)0x30 ,(byte)0x8d ,(byte)0x31 ,(byte)0x31 ,(byte)0x98 ,(byte)0xa2 ,(byte)0xe0 ,(byte)0x37 ,(byte)0x07 ,(byte)0x34};
		byte[] roundKey = { (byte)0x2b ,(byte)0x7e ,(byte)0x15 ,(byte)0x16 ,(byte)0x28 ,(byte)0xae ,(byte)0xd2 ,(byte)0xa6 ,(byte)0xab ,(byte)0xf7 ,(byte)0x15 ,(byte)0x88 ,(byte)0x09 ,(byte)0xcf ,(byte)0x4f ,(byte)0x3c};
		loadEK(roundKey);
		roundNumber=0;
		messageLength = state.length;
		//run program
		System.out.println("original: ");
		print(state);
		state = encrypt(state);
		System.out.println("-------------------------------------------------------------");
		System.out.println("cypherText: ");
		print(state);
		System.out.println("-------------------------------------------------------------");
		state = decrypt(state);
		System.out.println("plain: ");
		print(state);
		
		System.out.println("_____________________________________________________________");
		System.out.println();
		
		Scanner kdb = new Scanner(System.in);
		kdb.useDelimiter(System.getProperty("line.separator"));
		
		System.out.println("second test:");
		roundNumber=0;
		String secretKey = "SHHhHhhhHhhHhH!!";
		roundKey = secretKey.getBytes();	
		loadEK(roundKey);
		//take message wished to be encrypted
		System.out.print("enter message: ");
		String message = kdb.next();
		//turn message into byte array
		byte[] temp = message.getBytes();
		int x = temp.length;
		//store message length
		messageLength = x;
		byte [] smessage;
		//check if message needs to be padded so it fills up 16 byte blocks
		if(x%16 != 0){
			x = (x/16+1)*16;
			smessage = new byte [(x/16+1)*16];
			//fills smessage with message and pads
			for(int i = 0; i < smessage.length; i++){
				if(i < temp.length){
					smessage[i] = temp[i];
				}
				else{
					smessage[i] = (byte)0xff;
				}
			}
		}
		else //message doesnt need padding
			smessage = temp;
		//finds out how many 16 byte blocks there are
		x /= 16;
		//run program
		System.out.println("original: ");
		print(smessage);
		//sees which path do go to encrypt all blocks
		if(x <= 1){
			smessage = encrypt(smessage);			

		}
		else{
			int k = 0, l = 0;
			state = new byte [16];
			for(int i = 0; i < x; i++){
				//resets round number for block
				roundNumber=0;
				//breaks message into 16 byte states
				for(int j = 0; j < 16; j++){
					state[j] = smessage[k];
					k++;
				}
				state = encrypt(state);
				//sticks 16 byte state in side message
				for(int j = 0; j< 16; j++){
					smessage[l] = state[j];
					l++;
				}
			}
		}
		System.out.println("-------------------------------------------------------------");
		System.out.println("cypherText: ");
		print(smessage);
		System.out.println("-------------------------------------------------------------");
		//sees which path it needs to take to decrypt all 16 byte blocks
		if(x <= 1){
			smessage = decrypt(smessage);			
		}
		else{
			int k = 0, l = 0;
			state = new byte [16];
			for(int i = 0; i < x; i++){
				//resets round number for block
				roundNumber=176;
				//breaks up message into 16 byte states
				for(int j = 0; j < 16; j++){
					state[j] = smessage[k];
					k++;
				}
				state = decrypt(state);
				//puts state back into block
				for(int j = 0; j< 16; j++){
					smessage[l] = state[j];
					l++;
				}
			}
		}
		System.out.println("plain: ");
		print(smessage);
	}
}
