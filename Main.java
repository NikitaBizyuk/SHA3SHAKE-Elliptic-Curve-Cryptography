/*
 * Nikita Bizyuk
 * Professor Paulo Baretto
 * Summer 2025
 * 08-20-2025
 * SHA3SHAKE/Elliptic Curve Project - Part 1 and Part 2
 */
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.SecureRandom;

/**
 * This class is the blueprint for Part 1 and 2 of
 * the quarterly project. This class uses both the SHA3SHAKE class
 * and the Edwards class to execute various functions such as Encryption,
 * Decryption, Hashing, and MAC authentication.
 * @author bizyu
 */
public class Main {
    
    private static final SecureRandom random = new SecureRandom();
    private static final Edwards curve = new Edwards();
    public static void main(String[] args) {
        if (args.length == 0) {
            directions();
            return;
        }    
        String input = args[0].toLowerCase();       
        try {
            switch (input) {
                case "hash":
                    handleHashInput(args);
                    break;
                case "mac":
                    handleMacInput(args);
                    break;
                case "encrypt":
                    handleEncryptInput(args);
                    break;
                case "decrypt":
                    handleDecryptInput(args);
                    break;
                    // Part 2
                case "genkey":
                    handleGenKeyInput(args);
                    break;
                case "eciesenc":
                    handleECIESEncryptInput(args);
                    break;
                case "eciesdec":
                    handleECIESDecryptInput(args);
                    break;
                case "sign":
                    handleSignInput(args);
                    break;
                case "verify":
                    handleVerifyInput(args);
                    break;
                default:
                    System.err.println("Unknown command: " + input);
                    directions();
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * directions() prints directions onto the console/terminal 
     * that are needed to properly execute the program
     */
    private static void directions() {
        System.out.println("SHA3/SHAKE PART 1:");
        System.out.println("Directions:"
        		+ "\nStep 1: Open operating system terminal"
        		+ "\nStep 2: CD to file directory of project"
        		+ "\nStep 3:This assignment allows for several tasks to be executed."
        		+ " Example Input options are:"
        		+ "\n\t java Main hash nameOfDocument.txt"
        		+ "\n\t\t - Computes SHA-3 hashes of a specific file of your choice."
        		+ "\n\t java Main mac secret.txt mypassword 32"
        		+ "\n\t\t - Computes SHAKE MAC tag of a specified length"
        		+ " for a file under passphrase"
        		+ "\n\t java Main encrypt plain.txt cipher.enc mypassword"
        		+ "\n\t\t Encrypts inputfile to outputfile using a passphrase"
        		+ "\n\t java Main decrypt cipher.enc recovered.txt mypassword"
        		+ "\n\t\t - Decrypts input file to output file using passphrase");
        System.out.println("Elliptic Curve Part 2:" +
                "\n\tjava Main genkey mypassword keypair.pub" +
                "\n\t\t - Generate elliptic key pair and write public key to file" +
                "\n\tjava Main eciesenc data.txt encrypted.dat keypair.pub" +
                "\n\t\t - Encrypt file using ECIES under public key" +
                "\n\tjava Main sign document.txt signature.sig mypassword" +
                "\n\t\t - Sign file with schnorr using password - derived private key" +
                "\n\tjava Main verify document.txt signature.sig keypair.pub" +
                "\n\t\t - verify schnorr signature under public key");

    }
    
    /**
     * This method computes Hashes for a given input file.
     * Hash outputs come in 224, 256, 384, and 512 bit options.
     * @param args is the users input, which in this case
     * is for a file needed to be hashed
     * @throws IOException if the input is invalid (File name not provided,
     * or more then one file name was passed into the args array.
     */
    private static void handleHashInput(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("Invalid input:"
            		+ "\n\t -If attempting to hash, please type"
            		+ " [java Main hash (filename.txt)]");
            return;
        }      
        String filename = args[1];       
        byte[] fileData = Files.readAllBytes(Paths.get(filename));
        System.out.println("Computing SHA3 hash for: " + filename + "\n");
        byte[] sha3_224 = SHA3SHAKE.SHA3(224, fileData, null);
        byte[] sha3_256 = SHA3SHAKE.SHA3(256, fileData, null);
        byte[] sha3_384 = SHA3SHAKE.SHA3(384, fileData, null); 
        byte[] sha3_512 = SHA3SHAKE.SHA3(512, fileData, null);   
        System.out.println("SHA3-224: " + bytesToHex(sha3_224)
        		+ "\nSHA3-256: " + bytesToHex(sha3_256)
        		+ "\nSHA3-384: " + bytesToHex(sha3_384)
        		+ "\nSHA3-512: " + bytesToHex(sha3_512));      
    }
    
    /**
     * handleMacInput() computes SHAKE128 and SHAKE256 MAC tags
     * of a user specified length for a user specified file under
     * a specified pass phrase.
     * @param args arrays stores the input values needed
     * to compute the mac tag. These values are the file name,
     * pass phrase and length of the desired output.
     * @throws IOException throws an exception if the input is invalid.
     */
    private static void handleMacInput(String[] args) throws IOException {
        if (args.length != 4) {
            System.err.println("Invalid input:"
            		+ "\n\t -If attempting to compute MAC tag, please type"
            		+ " [java Main mac (filename.txt) (passphrase)"
            		+ " length]");
            return;
        }     
        String filename = args[1];
        String passphrase = args[2];
        int length = Integer.parseInt(args[3]);
        
        try {
            if (length <= 0) {
                throw new NumberFormatException("Length must be positive");
            }
        } catch (NumberFormatException e) {
            System.err.println("Invalid length: " + args[3]);
            return;
        }      
        byte[] fileData = Files.readAllBytes(Paths.get(filename));
        byte[] passphraseBytes = passphrase.getBytes();      
        System.out.println("Computing SHAKE MACs for: " + filename 
        		+ "\nPassPhrase = " + passphrase
        		+ "\nLength = " + length + " bytes\n");     
        byte[] shake128_mac = computeShakeMAC(128, passphraseBytes, fileData, length);
        byte[] shake256_mac = computeShakeMAC(256, passphraseBytes, fileData, length);      
        System.out.println("SHAKE128 MAC: " + bytesToHex(shake128_mac));
        System.out.println("SHAKE256 MAC: " + bytesToHex(shake256_mac));      
    }
    
    /**
     * handleEncryptInput() derives a symmetric encryption key from
     * the users given pass phrase using shake 128. The symmetric key is then
     * used to create a keystream. The keystream is XOR'd onto the plain text
     * which generates cipher text.
     * @param args stores the input and output files as well as the passphrase
     * needed to generate the symmetric key.
     * @throws IOException If the users input is invalid(not enough arguments or
     * to many arguments).
     */
    private static void handleEncryptInput(String[] args) throws IOException {
        if (args.length != 4) {
            System.err.println("Invalid input:"
            		+ "\n\t -If attempting to compute encrypt a file,"
            		+ " please type [java Main encrypt (inputFileName.txt)"
            		+ " (outputFileName2.enc) (passphrase)");
            return;
        }     
        String inputFile = args[1];
        String outputFile = args[2];
        String passphrase = args[3];
        byte[] fileData = Files.readAllBytes(Paths.get(inputFile));      
        // Derive symmetric key from passphrase using SHAKE-128 (128-bit output)
        byte[] symmetricKey = SHA3SHAKE.SHAKE(128, passphrase.getBytes(),
        		128, null);       
        byte[] nonce = new byte[16]; 
        random.nextBytes(nonce);       
        // Generate keystream using SHAKE-128 nonce and symmetric key
        byte[] combined = new byte[nonce.length + symmetricKey.length];
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(symmetricKey, 0, combined, nonce.length, symmetricKey.length);
        byte[] keystream = SHA3SHAKE.SHAKE(128, combined, fileData.length * 8, null);       
        // XOR plaintext with keystream = cipher text
        byte[] ciphertext = new byte[fileData.length];
        for (int i = 0; i < ciphertext.length; i++) {
            ciphertext[i] = (byte) (fileData[i] ^ keystream[i]);
        } 
        byte[] mac = computeMac(symmetricKey,ciphertext);    
        // cryptogram: nonce + ciphertext + mac
        byte[] cryptogram = new byte[nonce.length + ciphertext.length
                                     + mac.length];
        System.arraycopy(nonce, 0, cryptogram, 0, nonce.length);
        System.arraycopy(ciphertext, 0, cryptogram, nonce.length,
        		ciphertext.length);
        System.arraycopy(mac, 0, cryptogram, nonce.length +
        		ciphertext.length, mac.length);
        Files.write(Paths.get(outputFile), cryptogram);
        System.out.println("Encryption successful:\nInput file: " + inputFile +  
        		"\nOutput file: " + outputFile + 
        		"\nNonce: " + bytesToHex(nonce) + 
        		"\nMAC " + bytesToHex(mac));
    }
    
    
    /**
     * handleDecrypt() decrypts file that was previously encrypted.
     * passphrase utilized in encryption process is needed to properly
     * execute decryption. This subroutine also triggers the verifyMac()
     * method which verifies mac tag. 
     * @param args input file, output file, and passphrase
     * @throws IOException triggered if invalid input
     */
    private static void handleDecryptInput(String[] args) throws IOException {
        if (args.length != 4) {
            System.err.println("Usage: java Main decrypt <inputfile>"
            		+ " <outputfile> <passphrase>");
            return;
        }      
        String inputFile = args[1];
        String outputFile = args[2];
        String passphrase = args[3];       
        byte[] cryptogram = Files.readAllBytes(Paths.get(inputFile));
        // Parse cryptogram: nonce (16 bytes) || ciphertext || mac (32 bytes)
        if (cryptogram.length < 16 + 32) {
            throw new IllegalArgumentException("Cryptogram too short "
            		+ "(minimum 48 bytes required (Nonce + MAC))");
        }        
        byte[] nonce = new byte[16];
        byte[] mac = new byte[32];
        byte[] ciphertext = new byte[cryptogram.length - 16 - 32];
        System.arraycopy(cryptogram, 0, nonce, 0, 16);
        System.arraycopy(cryptogram, 16, ciphertext, 0, ciphertext.length);
        System.arraycopy(cryptogram, 16 + ciphertext.length, mac, 0, 32);    
        // Derive symmetric key from passphrase
        byte[] symmetricKey = SHA3SHAKE.SHAKE(128, passphrase.getBytes(),
        		128, null);
        // Generate keystream using SHAKE-128(nonce || key)
        byte[] combined = new byte[nonce.length + symmetricKey.length];
        System.arraycopy(nonce, 0, combined, 0, nonce.length);
        System.arraycopy(symmetricKey, 0, combined, nonce.length, symmetricKey.length);
        byte[] keystream = SHA3SHAKE.SHAKE(128, combined, ciphertext.length * 8, null);     
        // XOR ciphertext with keystream to generate plaintext
        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = (byte) (ciphertext[i] ^ keystream[i]);
        }
        Files.write(Paths.get(outputFile), plaintext);
        verifyMac(symmetricKey,ciphertext,mac);
        System.out.println("Decryption completed:"
        		+ "\n\tInput file: " + inputFile
        		+ "\n\tOutput file: " + outputFile
        		+ "\n\tNonce: " + bytesToHex(nonce)
        		+ "\n\tMAC verification status: Succesful");
    }

    /**
     * handleGenKeyInput() Generates elliptic key pair from a passphrase
     * and writes the public key to a file.
     * @param args stores (genkey, passphrase, outputFileName)
     * @throws IOException If file write fails to execute.
     */
    private static void handleGenKeyInput(String[] args) throws IOException {
        if(args.length != 3){
            System.err.println("Usage: java Main genkey <passphrase> <publickeyfile>");
            return;
        }
        String passphrase = args[1];
        String publickeyfile = args[2];
        byte[] keyBytes = SHA3SHAKE.SHAKE(128,passphrase.getBytes(),256,null);
        BigInteger s = new BigInteger(1, keyBytes).mod(Edwards.r);
        Edwards.Point V = curve.gen().mul(s);

        if(getX(V).testBit(0)){
            s = Edwards.r.subtract(s);
            V = V.negate();
        }

        byte[] pubKeyData = new byte[64];
        byte[] xBytes = toFixedBytes(getX(V), 32);
        byte[] yBytes = toFixedBytes(getY(V),32);
        System.arraycopy(xBytes, 0, pubKeyData, 0, 32);
        System.arraycopy(yBytes, 0, pubKeyData, 32, 32);
        Files.write(Paths.get(publickeyfile), pubKeyData);

        System.out.println("Key pair generated succesfully" +
                "\nPublic key written to: " + publickeyfile);
    }

    /**
     * handleECIESEncryptInput() encrypts a file using ECIES with a given
     * public key. Implements full ECIES: random k, shared secret, SHAKE key derivation,
     * XOR encryption, SHA3 MAC.
     * @param args stores user input in the form of
     *             (eciesenc, datafile, outputfile, publickeyfile).
     * @throws IOException if file operation fails to execute.
     */
    private static void handleECIESEncryptInput(String[] args) throws IOException{
        if(args.length != 4){
            System.err.println("Usage: java Main eciesenc <datafile> <outputfile> <publickeyfile>");
            return;
        }

        byte[] message = Files.readAllBytes(Paths.get(args[1]));
        byte[] pubKeyData = Files.readAllBytes(Paths.get(args[3]));

        byte[] xBytes = new byte[32], yBytes = new byte[32];
        System.arraycopy(pubKeyData, 0, xBytes, 0, 32);
        System.arraycopy(pubKeyData, 32, yBytes, 0, 32);
        Edwards.Point V = createPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));

        // Generate random k
        int rbytes = (Edwards.r.bitLength() + 7) >> 3;
        BigInteger k = new BigInteger(new SecureRandom().generateSeed(rbytes << 1)).mod(Edwards.r);

        // Compute W = k*V and Z = k*G
        Edwards.Point W = V.mul(k);
        Edwards.Point Z = curve.gen().mul(k);

        // Get ka and ke from SHAKE-256
        byte[] wyBytes = toFixedBytes(getY(W), 32);
        byte[] shake256Output = SHA3SHAKE.SHAKE(256, wyBytes, 512, null);
        byte[] ka = new byte[32], ke = new byte[32];
        System.arraycopy(shake256Output, 0, ka, 0, 32);
        System.arraycopy(shake256Output, 32, ke, 0, 32);

        // Encrypt: c = message XOR SHAKE-128(ke)
        byte[] keystream = SHA3SHAKE.SHAKE(128, ke, message.length * 8, null);
        byte[] c = new byte[message.length];
        for (int i = 0; i < message.length; i++) {
            c[i] = (byte) (message[i] ^ keystream[i]);
        }

        // Compute MAC: t = SHA3-256(ka || c)
        byte[] macInput = new byte[ka.length + c.length];
        System.arraycopy(ka, 0, macInput, 0, ka.length);
        System.arraycopy(c, 0, macInput, ka.length, c.length);
        byte[] t = SHA3SHAKE.SHA3(256, macInput, null);

        // Write cryptogram: Z.x || Z.y || t || c
        byte[] zxBytes = toFixedBytes(getX(Z), 32);
        byte[] zyBytes = toFixedBytes(getY(Z), 32);
        byte[] cryptogram = new byte[32 + 32 + 32 + c.length];
        int offset = 0;
        System.arraycopy(zxBytes, 0, cryptogram, offset, 32); offset += 32;
        System.arraycopy(zyBytes, 0, cryptogram, offset, 32); offset += 32;
        System.arraycopy(t, 0, cryptogram, offset, 32); offset += 32;
        System.arraycopy(c, 0, cryptogram, offset, c.length);

        Files.write(Paths.get(args[2]), cryptogram);
        System.out.println("ECIES encryption successful");
    }

    /**
     * handleECIESDecryptInput() Decrypts ECIES cryptogram
     * using a password derived private key.
     * parses cryptogram, derives key, veriifes mac, then XOR decrypts
     * message.
     * @param args user input in the format of
     *             (eciesdec, inputfile, outputfile, passphrase)
     * @throws IOException if file operation fails.
     */
    private static void handleECIESDecryptInput(String[] args) throws IOException{
        if (args.length != 4) {
            System.err.println("Usage: java Main eciesdec <inputfile> <outputfile> <passphrase>");
            return;
        }
        byte[] cryptogram = Files.readAllBytes(Paths.get(args[1]));
        String passphrase = args[3];
        // Lines 389 to 395 for Parsing cryptogram
        byte[] zxBytes = new byte[32], zyBytes = new byte[32], t = new byte[32];
        System.arraycopy(cryptogram, 0, zxBytes, 0, 32);
        System.arraycopy(cryptogram, 32, zyBytes, 0, 32);
        System.arraycopy(cryptogram, 64, t, 0, 32);
        byte[] c = new byte[cryptogram.length - 96];
        System.arraycopy(cryptogram, 96, c, 0, c.length);
        Edwards.Point Z = createPoint(new BigInteger(1, zxBytes), new BigInteger(1, zyBytes));
        // Derive private key
        byte[] keyBytes = SHA3SHAKE.SHAKE(128, passphrase.getBytes(), 256, null);
        BigInteger s = new BigInteger(1, keyBytes).mod(Edwards.r);
        if (curve.gen().mul(s).negate().equals(curve.gen().mul(s))) { // Check if we need to negate
            s = Edwards.r.subtract(s);
        }
        // Compute the value of W -> s * Z
        Edwards.Point W = Z.mul(s);
        // Get ka and ke
        byte[] wyBytes = toFixedBytes(getY(W), 32);
        byte[] shake256Output = SHA3SHAKE.SHAKE(256, wyBytes, 512, null);
        byte[] ka = new byte[32], ke = new byte[32];
        System.arraycopy(shake256Output, 0, ka, 0, 32);
        System.arraycopy(shake256Output, 32, ke, 0, 32);
        // lines 411 to 417 for Verifying MAC
        byte[] macInput = new byte[ka.length + c.length];
        System.arraycopy(ka, 0, macInput, 0, ka.length);
        System.arraycopy(c, 0, macInput, ka.length, c.length);
        byte[] expectedT = SHA3SHAKE.SHA3(256, macInput, null);
        if (!java.util.Arrays.equals(t, expectedT)) {
            throw new SecurityException("ECIES MAC verification failed");
        }
        // finally Decrypt
        byte[] keystream = SHA3SHAKE.SHAKE(128, ke, c.length * 8, null);
        byte[] message = new byte[c.length];
        for (int i = 0; i < c.length; i++) {
            message[i] = (byte) (c[i] ^ keystream[i]);
        }
        Files.write(Paths.get(args[2]), message);
        System.out.println("ECIES decryption successful");
    }

    /**
     * handleSIgnInput() generates Schnorr signature for file
     * using password derived private key.
     * Creates random nonce, computes challenge hash, produces
     * signature pair (h, z).
     * @param args user input in the form of
     *             (sign, datafile, signatureFile, passphrase)
     * @throws IOException if file operations fail.
     */
    private static void handleSignInput(String[] args) throws IOException{
        if (args.length != 4) {
            System.err.println("Usage: java Main sign <datafile> <signaturefile> <passphrase>");
            return;
        }
        byte[] message = Files.readAllBytes(Paths.get(args[1]));
        String passphrase = args[3];
        // Derive private key
        byte[] keyBytes = SHA3SHAKE.SHAKE(128, passphrase.getBytes(), 256, null);
        BigInteger s = new BigInteger(1, keyBytes).mod(Edwards.r);
        // Generate random k
        int rbytes = (Edwards.r.bitLength() + 7) >> 3;
        BigInteger k = new BigInteger(new SecureRandom().generateSeed(rbytes << 1)).mod(Edwards.r);
        // Compute U
        Edwards.Point U = curve.gen().mul(k);
        // lines 453 to 458 for Computing h
        byte[] uyBytes = toFixedBytes(getY(U), 32);
        byte[] hashInput = new byte[uyBytes.length + message.length];
        System.arraycopy(uyBytes, 0, hashInput, 0, uyBytes.length);
        System.arraycopy(message, 0, hashInput, uyBytes.length, message.length);
        byte[] hashBytes = SHA3SHAKE.SHA3(256, hashInput, null);
        BigInteger h = new BigInteger(1, hashBytes).mod(Edwards.r);
        // Compute z = (k - h*s) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(Edwards.r);
        // lines 462 to 468 for Writing signature
        byte[] signature = new byte[64];
        byte[] hBytes = toFixedBytes(h, 32);
        byte[] zBytes = toFixedBytes(z, 32);
        System.arraycopy(hBytes, 0, signature, 0, 32);
        System.arraycopy(zBytes, 0, signature, 32, 32);
        Files.write(Paths.get(args[2]), signature);
        System.out.println("Schnorr signature generated successfully");
    }

    /**
     * handleVerifyInput() verifies Schnorr signature against
     * message and public key. Parses signature, reconstructs
     * commitment point, compares challenge hashes.
     * @param args user input in the format of
     *             (verify, datafile, signaturefile, publicKeyFile)
     * @throws IOException if file operations fails.
     */
    private static void  handleVerifyInput(String[] args) throws IOException {
        if (args.length != 4) {
            System.err.println("Usage: java Main verify <datafile> <signaturefile> <publickeyfile>");
            return;
        }
        byte[] message = Files.readAllBytes(Paths.get(args[1]));
        byte[] signature = Files.readAllBytes(Paths.get(args[2]));
        byte[] pubKeyData = Files.readAllBytes(Paths.get(args[3]));
        // Parse signature
        byte[] hBytes = new byte[32], zBytes = new byte[32];
        System.arraycopy(signature, 0, hBytes, 0, 32);
        System.arraycopy(signature, 32, zBytes, 0, 32);
        BigInteger h = new BigInteger(1, hBytes);
        BigInteger z = new BigInteger(1, zBytes);
        // Parse public key
        byte[] xBytes = new byte[32], yBytes = new byte[32];
        System.arraycopy(pubKeyData, 0, xBytes, 0, 32);
        System.arraycopy(pubKeyData, 32, yBytes, 0, 32);
        Edwards.Point V = createPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
        // Compute U' = z*G + h*V
        Edwards.Point zG = curve.gen().mul(z);
        Edwards.Point hV = V.mul(h);
        Edwards.Point UPrime = zG.add(hV);
        // Compute h' = SHA3-256(U'.y || message) mod r
        byte[] uyPrimeBytes = toFixedBytes(getY(UPrime), 32);
        byte[] hashInput = new byte[uyPrimeBytes.length + message.length];
        System.arraycopy(uyPrimeBytes, 0, hashInput, 0, uyPrimeBytes.length);
        System.arraycopy(message, 0, hashInput, uyPrimeBytes.length, message.length);
        byte[] hashBytes = SHA3SHAKE.SHA3(256, hashInput, null);
        BigInteger hPrime = new BigInteger(1, hashBytes).mod(Edwards.r);
        boolean isValid = h.equals(hPrime);
        System.out.println("Schnorr signature verification: " + (isValid ? "VALID" : "INVALID"));
    }

    private static BigInteger getX(Edwards.Point point) {
        try {
            java.lang.reflect.Field field = point.getClass().getDeclaredField("x");
            field.setAccessible(true);
            return (BigInteger) field.get(point);
        } catch (Exception e) {
            throw new RuntimeException("Failed to access x coordinate", e);
        }
    }

    private static BigInteger getY(Edwards.Point point) {
        try {
            java.lang.reflect.Field field = point.getClass().getDeclaredField("y");
            field.setAccessible(true);
            return (BigInteger) field.get(point);
        } catch (Exception e) {
            throw new RuntimeException("Failed to access y coordinate", e);
        }
    }

    private static Edwards.Point createPoint(BigInteger x, BigInteger y) {
        return curve.getPoint(y, x.testBit(0));
    }

    private static byte[] toFixedBytes(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        } else if (bytes.length > length && bytes[0] == 0) {
            byte[] result = new byte[length];
            System.arraycopy(bytes, 1, result, 0, length);
            return result;
        } else if (bytes.length < length) {
            byte[] result = new byte[length];
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
            return result;
        }
        throw new IllegalArgumentException("BigInteger too large for " + length + " bytes");
    }

    /**
     * Helper method used to verify mac for bonus points
     * @param theKey is a byte array that stores the symmetric key.
     * @param theCipher is a byte array that stores the cipher text.
     * @param mac is a byte array that stores the mac tag.
     */
    private static void verifyMac(byte[] theKey, byte[] theCipher,
    		byte[] mac) {
    	SHA3SHAKE macSponge = new SHA3SHAKE();
        macSponge.init(256);
        macSponge.absorb(theKey);
        macSponge.absorb(theCipher);
        byte[] expectedMac = macSponge.digest();     
        if (!java.util.Arrays.equals(mac, expectedMac)) {
            throw new SecurityException("MAC verification failed - "
            		+ "data is either corrupt"
            		+ "\n or password is incorrect");
        }
    }
    
    /**
     * computeMAC() generates a mac tag using the symmetric key and
     * cipher text to detect any unauthorized modifications to the
     * cipher text.
     * @param theKey stores the symmetric key
     * @param theCipher stores the cipher text.
     * @return a value representing the mac tag to authenticate
     *  the encryption process.
     */
    private static byte[] computeMac(byte[] theKey, byte[] theCipher) {
        SHA3SHAKE macSponge = new SHA3SHAKE();
        macSponge.init(256);
        macSponge.absorb(theKey);
        macSponge.absorb(theCipher);
        return macSponge.digest();
    }
    
    /**
     * computeShakeMac() generates MAC tag of a specified length
     * using the shake algorithm to authenticate the integrity of
     * the users input data.
     * @param shakeVariant 128 or 256 for MAC computation
     * @param passphrase stores the users input password
     * @param data stores that data that needs to be authenticated
     * @param length represents the desired MAC tag length
     * @return A value representing the MAC tag of a specified length
     */
    private static byte[] computeShakeMAC(int shakeVariant,
    		byte[] passphrase, byte[] data, int length) {
        // Use static SHAKE method for proper SHAKE initialization
        byte[] combined = new byte[passphrase.length + data.length + 1];
        System.arraycopy(passphrase, 0, combined, 0, passphrase.length);
        System.arraycopy(data, 0, combined, passphrase.length, data.length);
        combined[combined.length - 1] = (byte)'T';
        
        return SHA3SHAKE.SHAKE(shakeVariant, combined, length * 8, null);
    }
    
    /**
     * bytesToHex() is a helper method used to convert bytes 
     * to hexadecimal values for better user readability.
     * @param bytes stores a byte array.
     * @return a String containing hexadecimal values.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b & 0xFF));
        }
        return result.toString();
    }
}