/**
 * This is a class for working with Vigenere ciphers and related/derived ciphers. It is limited to working with the 
 * ASCII character set from A to Z, parallel with this picture: 
 * https://upload.wikimedia.org/wikipedia/commons/9/9a/Vigen%C3%A8re_square_shading.svg
 * 
 * On my computer, bruteForce with a keyspace of 3 and cipher of 12 characters took 205 seconds.
 *
 * @author Logan May
 *
 */

import java.util.*;
import java.util.Arrays;

public class Vigenere {
  /**
   * Encrypts a string with a Vigenere cipher, which requires a key.
   *
   * @param key       String for the key
   * @param clear     String of clear text to be encrypted
   * @return          String of cipher text
   */
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
  /**
   * Decrypts a Vigenere cipher with the provided key
   *
   * @param key       String for the key
   * @param clear     String of cipher text to be decrypted
   * @return          String of clear text
   */
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
  /**
   * Attempts a brute force attack on a Vigenere cipher by attempting all possible keys. It prints all of the
   * key-cleartext pairs.
   *
   * @param keyspace  int for the size of the keyspace
   * @param cipher    String of cipher text to brute forced
   * 
   */
  public static void bruteForce(int keyspace, String cipher) {
    
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
    /**
   * Attempts a brute force attack on a Vigenere cipher by attempting all possible keys, but stops when a given
   * word is detected.
   *
   * @param keyspace  int for the size of the keyspace
   * @param scanWord  String for the word we're scanning for
   * @param cipher    String of cipher text to brute forced
   * @return key      String of the key that worked or "none" if the word was not found
   * 
   */
  public static String bruteForceScan(int keyspace, String scanWord, String cipher) {
    
    // Initialize
    String key = "";
    String clear;
    int[] keyAscii = new int[keyspace];
    Arrays.fill(keyAscii, 65);
    double iters = (Math.pow(26.0, (double) keyspace));
    boolean scan = false;

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
      
      // Check if the word is there
      scan = scan(scanWord, clear);
      
      // If it is, we're done
      if (scan) return key;

      // Otherwise, keep going, get next key
      key = nextKey(key);
    }
    // We couldn't find it.  return "none"
    return "none";
    
  }
  /**
   * Given a key, returns the next logical key in the keyspace (e.g. AA -> AB, AZ -> BA)
   *
   * @param key       String for the key
   * @return          String of the next logical key
   */
  public static String nextKey(String key) {
    
    // Initialize
    int keyspace = key.length();
    StringBuilder sb = new StringBuilder(key);
    
    // Get the next key if it's a special case
    if ( (int) key.charAt(keyspace - 1) == 90 ) {
      for (int i = 1; i < keyspace; i++) {
        if ( (int) key.charAt(keyspace - i) == 90 ) {
          sb.setCharAt(keyspace - i, 'A');
          int current = (int) sb.charAt(keyspace - (i + 1));
          char next = (char) (current + 1);
          sb.setCharAt(keyspace - (i + 1), next);
        }
      }
      
    // Fix format and return
    key = sb.toString();
    return key;
    }
    
    // Get the next key if it's a simple increment, fix format, and return
    else {
      int current = (int) sb.charAt(keyspace - 1);
      char next = (char) (current + 1);
      sb.setCharAt(keyspace - 1, next);
      key = sb.toString();
      return key;
    }
  }
  /**
   * Cleans the return string of an Array.toString() by removing brackets, spaces, and commas
   *
   * @param arrString String of the form of an Array.toString() call
   * @return          String without brackets, commas, or spaces 
   */
    public static String clean(String arrString) {
      
    // Initialize
    StringBuilder dec = new StringBuilder(arrString); // Stands for 'decremented'
    StringBuilder rec = new StringBuilder();          // Stands for 'recorded'
    
    // Remove brackets
    dec.deleteCharAt(arrString.length() - 1);
    dec.deleteCharAt(0);
    dec.append(".."); // accounts for last iteration of coming loop
    
    // Count how many letters
    int range = dec.length() / 3;
    
    // Once per letter
    for (int i = 0; i < range; i++) {
      rec.append(dec.charAt(0));  // Save the letter
      dec.deleteCharAt(0);        // Remove it
      dec.deleteCharAt(0);        // Remove the comma
      dec.deleteCharAt(0);        // Remove the soace
    }
    
    // Back to a string and return
    String result = rec.toString();
    return result;
  }
  /**
   * Encrypts cipher text with itself as a key. Used to create a more complicated, layered cipher.
   * 
   * @param cipher    String for the cipher text
   * @return          A cipher that's been encrypted yet again
   */
  public static String layer(String cipher) {
    String cipherNew = encrypt(cipher, cipher);
    return cipherNew;
  }
    /**
   * Scans cipher text to see if it contains a particular word.
   * 
   * @param scanWord  String for the word we are scanning for
   * @param cipher    String for the cipher text
   * @return          Boolean true if it the word is found, false if it is not
   */
  public static boolean scan(String scanWord, String cipher) {
    
    // Initialize
    StringBuilder sbCipher  = new StringBuilder(cipher); // An SB of the whole cipher
    StringBuilder sbSection = new StringBuilder();       // An SB to hold sections of the cipher we're checking for the word
    int end = scanWord.length();     // Index of the last letter of the section
    int last = cipher.length() - 1;  // Index of the last letter of the cipher
    boolean same = false;            // Holds the truth value of the comparison
    
    // Loop through each section of the cipher and check if it's the scanWord
    for (int start = 0; start < last - scanWord.length(); start++) {
      sbSection.append(sbCipher.substring(start, end));  // Grab the next section of the cipher
      same = sbSection.toString().equals(scanWord);      // Is it the scanWord?
      if (same) return same;                             // If it is, we're done
    }
    return same;
  }
}
