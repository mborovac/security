package labosi;

import java.math.BigInteger;
import java.util.Random;

public class KeyGenerator {
	
	static BigInteger p;
	static BigInteger q;
	static BigInteger n;
	static BigInteger m;
	static BigInteger e;
	static BigInteger d;
	
	public static void calculate(int number) {
		int size = number;
		Random rnd = new Random();
		p = BigInteger.probablePrime(size/2,rnd);
		q = p.nextProbablePrime();
		n = p.multiply(q);
		m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		e = getCoprime(m);
		d = e.modInverse(m);

		System.out.println("p: "+p);
		System.out.println("q: "+q);
		System.out.println("m: "+m);
		System.out.println("Modulus: "+n);
		System.out.println("Key size: "+n.bitLength());
		System.out.println("Public key: "+e);
		System.out.println("Private key: "+d);
	}
		   
	public static BigInteger getCoprime(BigInteger m) {
		Random rnd = new Random();
		int length = m.bitLength()-1;
		BigInteger e = BigInteger.probablePrime(length,rnd);
		while (!(m.gcd(e)).equals(BigInteger.ONE)) {
			e = BigInteger.probablePrime(length,rnd);
		}
		return e;
	}
}
