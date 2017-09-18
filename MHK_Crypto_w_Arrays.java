import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Random;
import java.util.Scanner;

/**
 * <p>
 * This implements Merkle-Hellman knapsack cryptosystem with arrays.
 * </p>
 * <p>
 * Details of Merkle-Hellman knapsack cryptosystem can be seen here:
 * <a href="https://en.wikipedia.org/wiki/Merkle-Hellman_knapsack_cryptosystem">
 * https://en.wikipedia.org/wiki/Merkle-Hellman_knapsack_cryptosystem
 * </a>
 * </p>
 *
 * @author Stephen Xie &lt;[redacted]@cmu.edu&gt;
 */
public class MHK_Crypto_w_Arrays {

    // w: the superincreasing sequence of integers that make up part of the private key
    //    and used for decryption
    // b: the public key sequence used for encryption
    private BigInteger[] w, b;
    // q: a random integer that's larger than the sum of w
    // r: a random integer that's coprime with q
    private BigInteger q, r;
    private Random rand = new Random();
    private static final int MAX_CHARS = 150;  // maximum number of characters allowed in a message
    private static final int BINARY_LENGTH = MAX_CHARS * 8;  // length of the longest message allowed in binary (a char is 8-bit long)
    private static final Charset UTF8 = Charset.forName("UTF-8");  // the program only processes UTF-8 encoded messages

    /**
     * Constructor
     */
    public MHK_Crypto_w_Arrays() {
        genKeys();
    }

    /**
     * <pre>
     * Generate public & private keys for encrypting / decrypting a message with a
     * given length; the public key is the array b, and the private key is (w, q, r)
     * combined.
     *
     * Pre-condition: the maximum characters allowed per message (MAX_CHARS) should be an integer greater than 0
     * Post-condition: w, b, q, r of this object are modified
     * </pre>
     */
    private void genKeys() {
        int maxBits = 50;
        // maximum number of bits of a randomly generated big integer; this affects the number scale of the
        // generated public / private keys below

        // w will be a superincreasing big integer array
        w = new BigInteger[BINARY_LENGTH];
        // initialize a random big integer as the starting point; since the range of the random number includes 0,
        // add 1 to it to be safe
        w[0] = new BigInteger(maxBits, rand).add(BigInteger.ONE);
        BigInteger sum = new BigInteger(w[0].toByteArray());  // sum of the w BigInteger array
        for (int i = 1; i < w.length; i++) {  // populate the array with superincreasing big integers
            w[i] = sum.add(new BigInteger(maxBits, rand).add(BigInteger.ONE));
            sum = sum.add(w[i]);
        }

        // q will be a random integer bigger than the sum of the array w
        q = sum.add(new BigInteger(maxBits, rand).add(BigInteger.ONE));
        // a simple selection for r: just pick q - 1 as it and q will always be coprime
        r = q.subtract(BigInteger.ONE);

        // generate the public key sequence
        b = new BigInteger[BINARY_LENGTH];
        for (int i = 0; i < b.length; i++)
            b[i] = w[i].multiply(r).mod(q);
    }

    /**
     * <pre>
     * Encrypt the given message.
     *
     * Pre-conditions:
     *      1. The length of the message (number of characters) must not exceed the maximum limit defined in this class.
     *      2. The message must not be an empty string.
     *      3. The message string is encoded in UTF-8.
     * Post-condition: the encrypted message is returned
     * </pre>
     *
     * @param message the message string to be encrypted
     * @return the ciphertext converted to string
     */
    public String encryptMsg(String message) {
        if (message.length() > MAX_CHARS)
            throw new IndexOutOfBoundsException("Maximum message length allowed is " + MAX_CHARS + ".");
        if (message.length() <= 0)
            throw new Error("Cannot encrypt an empty string.");

        // convert message to binary string
        String msgBinary = new BigInteger(message.getBytes(UTF8)).toString(2);
        // pad 0 to the left if the converted binary is not as long as the key sequences w and b
        if (msgBinary.length() < BINARY_LENGTH) {
            msgBinary = String.format("%0" + (BINARY_LENGTH - msgBinary.length()) + "d", 0) + msgBinary;
        }

        // produce the final encrypted message
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < msgBinary.length(); i++) {
            result = result.add(b[i].multiply(new BigInteger(msgBinary.substring(i, i+1))));
        }

        return result.toString();
    }

    /**
     * <pre>
     * Decrypt the given message.
     *
     * Pre-conditions: the supplied ciphertext must be able to convert to BigInteger type.
     * Post-condition: the decrypted message is returned
     * </pre>
     *
     * @param ciphertext the ciphertext
     * @return the decrypted message
     */
    public String decryptMsg(String ciphertext) {
        BigInteger tmp = new BigInteger(ciphertext).mod(q).multiply(r.modInverse(q)).mod(q);
        byte[] decrypted_binary = new byte[w.length];  // the decrypted message in binary

        for (int i = w.length - 1; i >= 0; i--) {
            if (w[i].compareTo(tmp) <= 0) {  // found the largest element in w which is less than or equal to tmp
                tmp = tmp.subtract(w[i]);
                decrypted_binary[i] = 1;
            } else {
                decrypted_binary[i] = 0;
            }
        }

        // convert byte[] to string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < decrypted_binary.length; i++) {
            sb.append(decrypted_binary[i]);
        }

        return new String(new BigInteger(sb.toString(), 2).toByteArray());
    }


    /**
     * Test driver
     */
    public static void main(String[] args) {
        MHK_Crypto_w_Arrays crypto = new MHK_Crypto_w_Arrays();
        System.out.println("Public and private keys have been generated.\n");
        Scanner input = new Scanner(System.in);
        String message;
        while (true) {
            System.out.println("Enter a string and I will encrypt it as single large integer:");
            message = input.nextLine();
            if (message.length() > MAX_CHARS)
                System.out.printf("\nYour message should have at most %d characters! Please try again.\n\n", MAX_CHARS);
            else if (message.length() <= 0)
                System.out.println("\nYou message should not be empty! Please try again.\n\n");
            else break;
        }


        System.out.println("\nClear text:");
        System.out.println(message);
        System.out.println("\nNumber of clear text bytes = " + message.getBytes().length);

        String encrypted = crypto.encryptMsg(message);
        System.out.println("\n\"" + message + "\"" + " is encrypted as:");
        System.out.println(encrypted);

        System.out.println("\nResult of decryption:");
        System.out.println(crypto.decryptMsg(encrypted));
    }

}
