package cryptosystem;

import java.math.BigInteger;
import edu.cmu.andrew.xiumingl.SinglyLinkedList;
import java.util.Scanner;

public class Cryptosystem {
	// store the private information about the public key and private key
	private static BigInteger q;
	private static BigInteger r;
	private static SinglyLinkedList w = new SinglyLinkedList();
	private static SinglyLinkedList b = new SinglyLinkedList();
	private static int strLen;

	// generate the keys
	public static void keyGeneration() {
		// create first element in the private key
		BigInteger initialNumber = new BigInteger(String.valueOf((int) (Math.random() * 100 + 1)));
		BigInteger sum = initialNumber;
		w.addAtEndNode(initialNumber);

		// create private key
		for (int i = 1; i < 640; i++) {
			BigInteger random = new BigInteger(String.valueOf((int) (Math.random() * 100 + 1)));
			BigInteger number = sum.add(random);
			w.addAtEndNode(number);
			sum = sum.add(number);
		}

		BigInteger random = new BigInteger(String.valueOf((int) (Math.random() * 100 + 1)));

		// create q which is greater than the sum
		q = sum.add(random);

		// create r which is coprime to q
		r = q.subtract(BigInteger.ONE);

		// create public key
		w.reset();
		while (w.hasNext()) {
			BigInteger h = new BigInteger(String.valueOf(w.next()));
			BigInteger key = h.multiply(r).mod(q);
			b.addAtEndNode(key);
		}
	}

	// encrypt the input text as BigInteger
	public static BigInteger encryption(String s) {
		BigInteger sum = BigInteger.ZERO;
		char[] strChar = s.toCharArray();
		strLen = strChar.length;

		// check if input string is too long
		if (strLen > 80) {
			System.out.println("Input String is too long!");
			return null;
		} else {
			System.out.println("Number of clear text bytes = " + strLen);
		}

		// change input string to binary string
		String result = "";
		for (int i = 0; i < strLen; i++) {
			String ele = Integer.toBinaryString((int) strChar[i]);
			int len = ele.length();
			while (len < 8) {
				ele = '0' + ele;
				len++;
			}
			result += ele;
		}

		char[] h = result.toCharArray();

		// compute the big Integer standing for ciphertext
		b.reset();
		for (int i = 0; i < 8 * strLen; i++) {
			BigInteger orin = new BigInteger(String.valueOf(b.next()));
			BigInteger bin = new BigInteger(String.valueOf(h[i]));
			sum = sum.add(orin.multiply(bin));
		}
		return sum;

	}

	// decrypt the ciphertext as plaintext
	public static String decryption(BigInteger s) {
		BigInteger num = r.modInverse(q);
		BigInteger dec = (s.multiply(num)).mod(q);
		String binStr = "";
		String plaintext = "";

		// construct 8-bit binary string standing for the input information
		for (int i = 8 * strLen - 1; i >= 0; i--) {
			BigInteger h = new BigInteger(String.valueOf(w.getObjectAt(i)));
			int res = h.compareTo(dec);
			if (res == -1 || res == 0) {
				dec = dec.subtract(h);
				binStr = "1" + binStr;

			} else if (res == 1)
				binStr = "0" + binStr;
		}
        
		// change binary string into characters
		for (int a = 0, b = 8; a < (8 * strLen); a += 8, b += 8) {
			String l = binStr.substring(a, b);
			int c = Integer.parseInt(l, 2);
			plaintext = plaintext + (char) c;
		}

		return plaintext;
	}

	// test driver
	public static void main(String[] args) {
		// generate the key
		keyGeneration();

		// read input of users
		System.out.println("Enter a string and I will encrypt it as single large integer:");
		Scanner sc = new Scanner(System.in);
		String s = sc.nextLine();
		System.out.println("Clear text: \n" + s);

		// encrypt the information
		BigInteger n = encryption(s);
		System.out.println(s + " is encrypted as: \n" + n + "\n");

		// decrypt the ciphertext
		String t = decryption(n);
		System.out.println("Result of decryption: \n" + t + "\n");

		sc.close();
	}

}
