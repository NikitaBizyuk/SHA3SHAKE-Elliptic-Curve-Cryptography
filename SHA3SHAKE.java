import java.util.Arrays;

/*
 * Nikita Bizyuk
 * Professor Paulo Baretto
 * Summer 2025
 * 07-12-2025
 * SHA3SHAKE Project - Part 1
 */

/**
 * This class recreates SHA3 and SHAKE algorithms.
 * This implementation follows the FIPS PUB 202 specifications.
 * Reference implementations consulted for verification include:
 * - Saarinen's tiny_sha3: hhtps://github.com/mjosaarinen/tiny_sha3
 * SHA3 output options are 224, 256, 384, and 512.
 * @author bizyu
 *
 */
public class SHA3SHAKE {
    
    private long[] myState;  
    private byte[] myBuffer;
    private int myBufferPos;  
    private int myRate;
    private int myCapacity;
    private int mySuffix;   
    private boolean isInitialized;
    private boolean isSqueezed;
    private boolean isShake;
    
    
    // Round constants for keccak,based on FIPS PUB 202 specification
    // Also referenced in Saarinen's tiny_sha3 implementation
    private static final long[] ROUND_CONSTANTS = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
        0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
        0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
        0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
        0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    
    // Rho step Rotation offsets 
    private static final int[] RHO_OFFSETS = {
        0, 1, 62, 28, 27, 36, 44,
        6, 55, 20, 3, 10, 43, 25,
        39, 41, 45, 15, 21, 8, 18,
        2, 61, 56, 14
    };
    
    public SHA3SHAKE() {
        myState = new long[25];
        myBuffer = new byte[200]; 
        isInitialized = false;
        isSqueezed = false;
        isShake = false;
    }
    
    /**
     * Initialize SHA-3/SHAKE sponge and resets 1600 bit state
     * to all zeros.
     * The suffix for SHA-3 is 224, 256, 384, or 512
     * The suffix for SHAKE is 128 or 256 (security level)
     * @param suffix stores the output bit length (SHA-3) or security level (SHAKE)
     */
    public void init(int suffix) {
        this.mySuffix = suffix;
        if(mySuffix == 224) {
        	myCapacity = 448;
        	myRate = 1152;
        	isShake = false;
        } else if (mySuffix == 256) {
        	// Always default to SHA-3-256 for init(256)
        	myCapacity = 512;
        	myRate = 1088;
        	isShake = false;
        } else if (mySuffix == 384) {
        	myCapacity = 768;
        	myRate = 832;
        	isShake = false;
        } else if(mySuffix == 512) {
        	myCapacity = 1024;
        	myRate = 576;
        	isShake = false;
        } else if(mySuffix == 128) {
        	// SHAKE-128
        	myCapacity = 256;
        	myRate = 1344;
        	isShake = true;
        } else {
        	throw new IllegalArgumentException("Invalid suffix:" + suffix);
        }	
        Arrays.fill(myState, 0L);
        myBufferPos = 0;
        isInitialized = true;
        isSqueezed = false;
    }
    
    /**
     * Private method to initialize SHAKE variants properly
     * This ensures SHAKE gets the right parameters without confusion
     */
    private void initForSHAKE(int suffix) {
        this.mySuffix = suffix;
        this.isShake = true; 
        if (suffix == 128) {
            myCapacity = 256;
            myRate = 1344;
        } else if (suffix == 256) {
            myCapacity = 512;
            myRate = 1088;
        } else {
            throw new IllegalArgumentException("Invalid SHAKE suffix: " + suffix);
        }     
        Arrays.fill(myState, 0L);
        myBufferPos = 0;
        isInitialized = true;
        isSqueezed = false;
    }
    
    /**
     * Absorb input data in blocks of size R into the buffer.
     * xor the R sized buffer with the state, permute the xor'd output. 
     * Then refill buffer and repeat if there is data left over.
     * @param data stores input data in byte format
     * @param pos stores the starting position of the
     * array needing to be absorbed.
     * @param len stores the ending index position of absorption.
     */
    public void absorb(byte[] data, int pos, int len) {
    	if (!isInitialized) {
            throw new IllegalStateException("Sponge has not been initialized");
        }
        if (isSqueezed) {
            throw new IllegalStateException("Cannot absorb after squeezing");
        }       
        int rateBytes = myRate / 8;   
        while (len > 0) {
            int bytesToCopy = Math.min(len, rateBytes - myBufferPos);    
            System.arraycopy(data, pos, myBuffer, myBufferPos, bytesToCopy);
            myBufferPos += bytesToCopy;
            pos += bytesToCopy;
            len -= bytesToCopy;
            if (myBufferPos == rateBytes) {
                // XOR buffer into 1600 bit state
                for (int i = 0; i < rateBytes; i += 8) {
                    int stateIdx = i / 8;
                    if (stateIdx < myState.length) {
                        myState[stateIdx] ^= bytesToLong(myBuffer, i);
                    }
                }
                keccak();
                myBufferPos = 0;
            }
        }
    }
    
    /**
     * Overridden method for absorb which does not include the 
     * "pos" argument. Starting position is 0.
     * @param data stores the input in bytes
     * @param len stores the ending index position needed to be absorbed.
     */
    public void absorb(byte[] data, int len) {
        absorb(data, 0, len);
    }
    
    /**
     * Overridden method for absorb, does not include "pos"
     * or "len". Starting position is zero, and the data array as
     * a whole is absorbed.
     * @param data stores the input data in bytes.
     */
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }
    
    /**
     * Squeeze() outputs a chunk of hashed bytes from the sponge.
     * this method is to be called as many times as needed to extract
     * the total desired number of bytes.
     * @param output byte array
     * @param len stores the desired number of squeezed bytes
     * @return output buffer containing the final hash value.
     */
    public byte[] squeeze(byte[] out, int len) {
        if (!isInitialized) {
            throw new IllegalStateException("Sponge not initialized");
        }     
        if (!isSqueezed) {
            applyPadding();
            isSqueezed = true;
            myBufferPos = 0;
        }     
        int rateBytes = myRate / 8;
        int outPos = 0;      
        while (outPos < len) {           
            // If we need fresh output, extract state to buffer
            if (myBufferPos == 0) {
                for (int i = 0; i < rateBytes && i < myBuffer.length; i += 8) {
                    int stateIndex = i / 8;
                    if (stateIndex < myState.length) {
                        longToBytes(myState[stateIndex], myBuffer, i);
                    }
                }
            }                  
            int availableBytes = rateBytes - myBufferPos;
            int bytesToCopy = Math.min(len - outPos, availableBytes); 
            System.arraycopy(myBuffer, myBufferPos, out, outPos, bytesToCopy);
            myBufferPos += bytesToCopy;
            outPos += bytesToCopy;       
            if (myBufferPos >= rateBytes && outPos < len) {
                keccak();
                myBufferPos = 0;
            }
        }        
        return out;
    }
    
    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the 
     * total desired number of bytes.
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) {
        byte[] out = new byte[len];
        return squeeze(out, len);
    }
    
    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     * @param out hash value buffer
     * @return the val buffer containing the desired hash value
     */
    public byte[] digest(byte[] out) {
        if (isShake) {
            throw new IllegalStateException("digest() not supported for SHAKE");
        }      
        int digestLen = mySuffix / 8;
        if (out == null) {
            out = new byte[digestLen];
        }    
        return squeeze(out, digestLen);
    }
    
    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        if (isShake) {
            throw new IllegalStateException("digest is not supported for SHAKE");
        }       
        int digestLen = mySuffix / 8;
        return squeeze(digestLen);
    }
    
    /**
     * Compute SHA-3 224,256,384,512 on byte[] theInput.
     * @param suffix desired output length 
     * in bits is 224, 256, 384, or 512
     * @param input data to be hashed
     * @param out hash value buffer (if null, this
     *  method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] input, byte[] out) {
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);
        sponge.absorb(input);    
        if (out == null) {
            out = new byte[suffix / 8];
        }       
        return sponge.digest(out);
    }
    
    /**
     * Compute  SHAKE-128 or 256 on byte[]x
     * with output bitlength L.
     * @param suffix desired security
     * level (either 128 or 256)
     * @param x data to be hashed
     * @param l desired output length in
     * bits (must be a multiple of 8)
     * @param out hash value buffer (if null, 
     * this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHAKE(int suffix, byte[] x, int L, byte[] out) {
        if (L % 8 != 0) {
            throw new IllegalArgumentException("Output length must be a multiple of 8");
        }   
        SHA3SHAKE sponge = new SHA3SHAKE();
        
        // Use the private method to properly initialize SHAKE
        sponge.initForSHAKE(suffix);
        sponge.absorb(x);     
        
        int outBytes = L / 8;
        if (out == null) {
            out = new byte[outBytes];
        }      
        return sponge.squeeze(out, outBytes);
    }
    
    /**
     * applyPadding() applies the appropriate padding to
     * finalize the absorption phase. This method
     * implements the 10*1 padding method which is
     * required by the Keccak sponge construction,
     * with domain separation to 
     * distinguish between SHA-3 and SHAKE:
     * SHA-3 official NIST standard domain separator: 6
     * SHAKE official NIST Standard domain separator: 31
     */
    private void applyPadding() {
    	int rateBytes = myRate / 8;
    	// Domain separation values from FIPS PUB 202
    	byte domainSep; 
    	if(isShake) {
         	domainSep = (byte)0x1F; // SHAKE NIST domain separator (31 decimal = 0x1F hex)
         } else {
         	domainSep = (byte)0x06; // SHA3 NIST domain separator (6 decimal = 0x06 hex)
         }
        myBuffer[myBufferPos] = domainSep;
        myBufferPos++;     
        while (myBufferPos < rateBytes) {
            myBuffer[myBufferPos] = 0;
            myBufferPos++;
        }
        myBuffer[rateBytes - 1] |= (byte) 0x80;       
        // XOR padded block into state
        for (int i = 0; i < rateBytes; i += 8) {
            int stateIdx = i / 8;
            if (stateIdx < myState.length) {
                myState[stateIdx] ^= bytesToLong(myBuffer, i);
            }
        }
        keccak();
        myBufferPos = 0;
    }
    
    /**
     * Keccak permutation implementation follows FIPS PUB 202.
     * Algorithm structure inspired by Saarinen's C implementation
     * keccak algorithm applies to the
     * 1600 bit state stored in the myState array.
     * The keccak algorithm consists of 5 steps which are
     * theta, rho, pi, chi, and iota. These 5 steps are
     * repeated 24 times.
     */
    private void keccak() {
        long[] bc = new long[5];   
        for (int round = 0; round < 24; round++) {
            thetaStep(bc);
            rhoStep();
            piStep(bc);
            chiStep(bc);
            iotaStep(round);
        }
    }
    
    /**
     * thetaStep() step 1 of 5 in keccak. Its purpose
     * is to mix each column with its neighboring columns
     * to spread changes across the entire state.
     * This is done by calculating parity of each columns,
     * mix each columns with left neighbor + rotated right corner,
     * then finally applying the mixing effect to every column
     * in that column.
     * @param bc[] temporary workspace for calculations.
     */
    private void thetaStep(long[] bc) {
        for (int i = 0; i < 5; i++) {
            bc[i] = myState[i] ^ myState[i + 5] ^ myState[i + 10]
            		^ myState[i + 15] ^ myState[i + 20];
        }
        for (int i = 0; i < 5; i++) {
            long t = bc[(i + 4) % 5] ^ rotateLeft(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                myState[j + i] ^= t;
            }
        }
    }

    /**
     * rhoStep() step 2 of 5 rotates bits within each lane.
     * Each of the 25 lanes gets rotated by a different amount
     * to spread bit changes around within each 64-bit word
     */
    private void rhoStep() {
        for (int i = 0; i < 25; i++) {
            myState[i] = rotateLeft(myState[i], RHO_OFFSETS[i]);
        }
    }

    /**
     * keccak step 3 of 5,shuffles lane positions.
     * Each lane is moved to a new position
     * in the 5x5 grid using the formula: 
     * (x,y) → (y, 2x+3y mod 5).
     * @param bc temporary workspace 
     * for calculations.
     */
    private void piStep(long[] bc) {
    	 long[] newState = new long[25];
    	    for (int x = 0; x < 5; x++) {
    	        for (int y = 0; y < 5; y++) {
    	            int oldIdx = index(x, y);
    	            int newIdx = index(y, (2 * x + 3 * y) % 5);
    	            newState[newIdx] = myState[oldIdx];
    	        }
    	    }
    	    myState = newState;
    }
    
    /**
     * keccak step 4 of 5. Applies
     * non linear mixing to rows.
     * Processes each row independently
     * using the formula: a[i] = a[i] XOR 
     * ((NOT a[i+1]) AND a[i+2]).
     * @param bc temporary workspace 
     * for calculations.
     */
    private void chiStep(long[] bc) {
        for (int j = 0; j < 25; j += 5) {
            // Copy row to temporary
            for (int i = 0; i < 5; i++) {
                bc[i] = myState[j + i];
            }
            for (int i = 0; i < 5; i++) {
                myState[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
    }

    /**
     * Keccak step 5 of 5, adds round constants.
     * XORs a unique constant into the first lane
     * to break symmetry and make each round different.
     * Without this step, all 24 rounds would be
     * identical.
     * @param round selects which constant to use.
     */
    private void iotaStep(int round) {
        myState[0] ^= ROUND_CONSTANTS[round];
    }
    
    /**
     * converts 2D coordiante into a 
     * 1D array index.
     * @param x stores the x coordinate.
     * @param y stores the y coordinate.
     * @return 1D array index.
     */
    private int index(int x, int y) {
        return 5 * y + x;
    }
    
    /**
     * Rotates a long value by a specified
     * number of bits.
     * @param value sores the long value to rotate.
     * @param bits stores the number of bits needed to 
     * rotate to the left.
     * @return The rotated long value.
     */
    private long rotateLeft(long value, int bits) {
        return (value << bits) | (value >>> (64 - bits));
    }
    
    /**
     * Converts 8 bytes to a long value in
     * little endian order.
     * @param bytes the byte array to read from.
     * @param offset stores the starting positions
     * in the byte array.
     * @return The resulting long value.
     */
    private long bytesToLong(byte[] bytes, int offset) {
        long result = 0;
        for (int i = 0; i < 8 && offset + i < bytes.length; i++) {
            result |= ((long) (bytes[offset + i] & 0xFF)) << (8 * i);
        }
        return result;
    }
    
    /**
     * converts long data type to 8 bytes.
     * @param value long value to convert.
     * @param bytes byte array to write to.
     * @param offset starting position in byte array.
     */
    private void longToBytes(long value, byte[] bytes, int offset) {
        for (int i = 0; i < 8 && offset + i < bytes.length; i++) {
            bytes[offset + i] = (byte) (value >>> (8 * i));
        }
    }
}