/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * Author: Logan May
 *
 * Email: mayl2@misericordia.edu
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * Description: This class is for working with Vigenere ciphers. This file contains 4 functions and a main:
 *
 * * encrypt(): It takes a key and cleartext and encrypts it with the Vigenere cipher
 *
 * * decrypt(): It takes a key and ciphertext and decrypts it with the Vignenere cipher
 *
 * * crack():   It takes a variable that indicates the length of the keyspace and ciphertext. It performs a brute
 * * * force attack on the cipher with all keys in the provided keyspace by calling decrypt() and nextKey(). It
 * * * prints the result of each attempt to the interactions panel.
 *
 * * nextKey(): It takes a key and generates the next key. A becomes B. AA becomes AB. AZ becomes BA. Etc. When
 * * * called from a loop, as it is in crack(), it can generate all the keys in a given keyspace (e.g. for a space
 * * * of 3, you can get everything from AAA to ZZZ).
 *
 * * clean(): It takes an array.toString(), gets rid of the brackets and commas, and returns a clean String
 *
 * * layer(): It takes text and encrypts it with itself as the key.
 *
 * * main() is used to call encrypt(), decrypt(), or crack() with given cleartext, ciphertext, and/or keyspace
 *
 * One thing I ought to mention about the configuration is that it is set up to work with only a small portion
 * of the ASCII character set (specifically from A-Z). It can be adjusted to work with other intervals, but at
 * the moment the Vigenere cipher employed is parallel with this table:
 * https://upload.wikimedia.org/wikipedia/commons/9/9a/Vigen%C3%A8re_square_shading.svg
 *
 * time - keyspace = 3, 2'45" (205 seconds)
 * assume for 5 -> (138580 seconds)
 * 8 -> 2435682080
 * 10 -> 1646521086080
 *
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * ** * * * * * * * * * * * * * * * * * * *
*/

import java.util.*;
import java.util.Arrays;

public class Vigenere {

  public static String encrypt(String key, String clear) {

    // Initialize varibles and arrays
    int keyLength = key.length();
    int clearLength = clear.length();
    int[]  keyAscii = new int[keyLength];
    int[]  clearAscii = new int[clearLength];
    String[] cipherString = new String[clearLength];
    int[]  cipherAscii = new int[clearLength];;
    String cipher;

    // Store Ascii values of each character of the key
    for(int i = 0; i < key.length(); i++) {
      keyAscii[i] = (int) key.charAt(i);
    }

    // Store Ascii values of each character of the cleartext
    for (int i = 0; i < clear.length(); i++) {
      clearAscii[i] = (int) clear.charAt(i);
    }

    // Create ciphertext
    int j = 0;
    for (int i = 0; i < clear.length(); i++) {
      cipherAscii[i] = (keyAscii[j] - 65) + clearAscii[i];
      if (cipherAscii[i] > 90) cipherAscii[i] = cipherAscii[i] - 26;
      cipherString[i] = Character.toString ((char) cipherAscii[i]);
      j++;
      if (j == key.length()) j = 0;
    }

    // Clean up the string from cipherString[]
    cipher = clean(Arrays.toString(cipherString));

    return cipher;
  }

  public static String decrypt(String key, String cipher) {

    // Initialize varibles and arrays
    int keyLength = key.length();
    int cipherLength = cipher.length();
    int[]  keyAscii = new int[keyLength];
    int[]  cipherAscii = new int[cipherLength];
    String[] clearString = new String[cipherLength];
    int[]  clearAscii = new int[cipherLength];;
    String clear;

    // Store the key as an array of chars and store the Ascii values
    for(int i = 0; i < key.length(); i++) {
      keyAscii[i] = (int) key.charAt(i);
    }

    // Store the cipher as an array of chars and store the Ascii values
    for (int i = 0; i < cipher.length(); i++) {
      cipherAscii[i] = (int) cipher.charAt(i);
    }

    // Create ciphertext
    int j = 0;
    for (int i = 0; i < cipher.length(); i++) {
      clearAscii[i] = cipherAscii[i] - (keyAscii[j] - 65);
      if (clearAscii[i] < 65) clearAscii[i] = clearAscii[i] + 26;
      clearString[i] = Character.toString ((char) clearAscii[i]);
      j++;
      if (j == key.length()) j = 0;
    }

    // Clean up the String from clearString[]
    clear = clean(Arrays.toString(clearString));

    return clear;
  }

  public static void crack(int keyspace, String cipher) {
    // Initialize
    String key = "";
    String clear;
    int[] keyAscii = new int[keyspace];
    Arrays.fill(keyAscii, 65);
    double iters = (Math.pow(26.0, (double) keyspace));

    // Form string from array of Ascii values
    StringBuilder sb = new StringBuilder();
    for (int j = 0; j < keyspace; j++) {
      sb.append( (char) keyAscii[j] );
    }
    key = sb.toString();

    // Try every possible key
    for (int i = 0; i < iters; i++) {

      // Decrypt this key
      clear = decrypt(key, cipher);

      // Print
      System.out.println(key + ": " + clear);

      // Get next key
      key = nextKey(key);
    }
  }

  public static String nextKey(String key) {
    int keyspace = key.length();
    StringBuilder sb = new StringBuilder(key);
    if ( (int) key.charAt(keyspace - 1) == 90 ) {
      for (int i = 1; i < keyspace; i++) {
        if ( (int) key.charAt(keyspace - i) == 90 ) {
          sb.setCharAt(keyspace - i, 'A');
          int current = (int) sb.charAt(keyspace - (i + 1));
          char next = (char) (current + 1);
          sb.setCharAt(keyspace - (i + 1), next);
        }
      }
    key = sb.toString();
    return key;
    }
    else {
      int current = (int) sb.charAt(keyspace - 1);
      char next = (char) (current + 1);
      sb.setCharAt(keyspace - 1, next);
      key = sb.toString();
      return key;
    }
  }

    public static String clean(String arrString) {
    StringBuilder dec = new StringBuilder(arrString);
    StringBuilder rec = new StringBuilder();
    dec.deleteCharAt(arrString.length() - 1);
    dec.deleteCharAt(0);
    dec.append("..");
    int range = dec.length() / 3;
    for (int i = 0; i < range; i++) {
      rec.append(dec.charAt(0));
      dec.deleteCharAt(0);
      dec.deleteCharAt(0);
      dec.deleteCharAt(0);
    }
    String result = rec.toString();
    return result;
  }

  public static String layer(String cipher) {
    String cipherNew = encrypt(cipher, cipher);
    return cipherNew;
  }

  public static void main(String args[]) {

    // Initialize values
    String key = "LEMON";
    String clear = "ATTACKATDAWN";
    String cipher = encrypt(key, clear);
    String cipher2 = layer(cipher);
    String cipher3 = decrypt(cipher, cipher2);
    System.out.println(cipher + "\n" + cipher3);
    //int keyspace = 3;


  }
}
