package secureserver;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class SecureServer {

    private static ServerSocket serverSocket;
    private static Socket clientSocket;
    private static InputStreamReader inputStreamReader;
    private static BufferedReader bufferedReader;
    private static String message = null;
    private static PrintWriter printWriter;
    private static SecureRandom secureRandom;
    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey, publicKeyofClient;
    private static KeyPairGenerator keyPairGenerator;
    private static KeyPair keyPair;

    public static void main(String[] args) throws ShortBufferException {
        int stage_count = 0;

        try {
            serverSocket = new ServerSocket(4444); // Server socket

        } catch (IOException e) {
            System.out.println("Could not listen on port: 4444 \n\n" + e.getMessage());
        }

// Generating RSA key-pair.
        secureRandom = new SecureRandom();
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
        }

        keyPairGenerator.initialize(2048, secureRandom);
        keyPair = keyPairGenerator.generateKeyPair();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();

//        // RSA encryption test.
//        Cipher ciphertest = null;
//        try {
//            ciphertest = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
//        } catch (NoSuchAlgorithmException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (NoSuchPaddingException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        try {
//            ciphertest.init(Cipher.ENCRYPT_MODE, publicKey);
//        } catch (InvalidKeyException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        byte[] ct = null;
//        try {
//            ct = ciphertest.doFinal("owlstead".getBytes(StandardCharsets.UTF_16));
//        } catch (IllegalBlockSizeException | BadPaddingException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        }
//
//        // RSA decryption test.
//        Cipher decryption = null;
//        try {
//            decryption = Cipher.getInstance("RSA/ECB/OAEPPadding");
//        } catch (NoSuchAlgorithmException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (NoSuchPaddingException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT);
//        try {
//            decryption.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
//        } catch (InvalidKeyException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (InvalidAlgorithmParameterException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        byte[] pt = null;
//        try {
//            pt = decryption.doFinal(ct);
//        } catch (IllegalBlockSizeException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        } catch (BadPaddingException ex) {
//            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        System.out.println(new String(pt, StandardCharsets.UTF_16));
// Generating AES key.        
        secureRandom = new SecureRandom();
        KeyGenerator kg = null;
        try {
            kg = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        kg.init(128, secureRandom);
        SecretKey ServerSecretKey = kg.generateKey();
        byte[] ServerAES = ServerSecretKey.getEncoded();
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream("ServerAES");
        } catch (FileNotFoundException ex) {
            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        ObjectOutputStream objectOutputStream = null;
        try {
            objectOutputStream = new ObjectOutputStream(fileOutputStream);
        } catch (IOException ex) {
            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            objectOutputStream.write(ServerAES);
        } catch (IOException ex) {
            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            objectOutputStream.close();
        } catch (IOException ex) {
            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
        }

        System.out.println(ServerAES.length);
        System.out.print("Server's RSA public key is:\n" + publicKey);

        System.out.println("Server started. Listening to the port 4444");

        while (true) {
            try {

                clientSocket = serverSocket.accept(); // accept the client connection
                switch (stage_count) {
                    case 0:
                        // Receive Client's RSA public key.

                        System.out.println("Step number: " + stage_count);

                        inputStreamReader = new InputStreamReader(clientSocket.getInputStream());
                        bufferedReader = new BufferedReader(inputStreamReader); // get the client message
                        message = bufferedReader.readLine();
                        System.out.println(message);

                        String ClientModulus = message.substring(28, 540),
                         ClientPublicExponent = message.substring(556, 561);

                        // Below is a test line.
//                        System.out.println(ClientModulus + "\n" + ClientPublicExponent + "\n\n");
                        
                        BigInteger bigInteger = new BigInteger(ClientModulus, 16),
                         bigInteger1 = new BigInteger(ClientPublicExponent);

                        RSAPublicKeySpec keyspec = new RSAPublicKeySpec(bigInteger, bigInteger1);
                         {
                            try {
                                KeyFactory kf = KeyFactory.getInstance("RSA");
                                try {
                                    publicKeyofClient = (RSAPublicKey) kf.generatePublic(keyspec);
                                } catch (InvalidKeySpecException ex) {
                                    Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
                                }
                            } catch (NoSuchAlgorithmException ex) {
                                Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }

                        System.out.println("Client's RSA public key (generated) is:\n" + publicKeyofClient);

                        inputStreamReader.close();
                        clientSocket.close();
                        ++stage_count;
                        break;

                    case 1:
                        // Send Server's RSA public key.

                        System.out.println("Step number: " + stage_count);

                        printWriter = new PrintWriter(clientSocket.getOutputStream(), true);
                        printWriter.write(publicKey.toString()); // write the message to output stream

                        printWriter.flush();
                        printWriter.close();
                        clientSocket.close(); // closing the connection
                        ++stage_count;
                        break;

                    case 2:
                        // Send AES key to Client.

                        System.out.println("Step number: " + stage_count);

                        Cipher c = null;
                        try {
                            c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
                            Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
                        }
                         {
                            try {
                                c.init(Cipher.ENCRYPT_MODE, publicKeyofClient);
                            } catch (InvalidKeyException ex) {
                                Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                        byte[] encodedBytes = null;
                         {
                            try {
                                encodedBytes = c.doFinal(ServerSecretKey.getEncoded());
                            } catch (IllegalBlockSizeException | BadPaddingException ex) {
                                Logger.getLogger(SecureServer.class.getName()).log(Level.SEVERE, null, ex);
                            }
                        }
                         
                         // Test line of code.
//                        System.out.println("Sent data size: " + encodedBytes.length);

                        OutputStream outputStream;
                        outputStream = clientSocket.getOutputStream();
                        outputStream.write(encodedBytes, 0, encodedBytes.length);

                        outputStream.flush();
                        outputStream.close();
                        clientSocket.close(); // closing the connection
                        ++stage_count;
                        break;

                    case 3:
                        // Receive AES key from Client.

                        System.out.println("Step number: " + stage_count);

                        int bytesRead;
                        int current = 0;
                        FileOutputStream fos = null;
                        byte[] EncryptedClientAES = new byte[100000];
                        InputStream is = clientSocket.getInputStream();
                        fos = new FileOutputStream("ClientAESFile");
                        BufferedOutputStream bos = new BufferedOutputStream(fos);
                        bytesRead = is.read(EncryptedClientAES, 0, EncryptedClientAES.length);
                        current = bytesRead;
                        
                        // Test line of codes.
//                        System.out.println("1. Size of read data: " + current);
//                        do {
//                            bytesRead = is.read(EncryptedClientAES, current, (EncryptedClientAES.length - current));
//                            if (bytesRead >= 0) {
//                                current += bytesRead;
//                            }
//                        } while (bytesRead > -1);

                        bos.write(EncryptedClientAES, 0, current);

                        bos.flush();
                        bos.close();
                        fos.close();
                        clientSocket.close();

                        // Test line of codes.
                        // Decryption of received data to get back the AES key cane be done here with a modification, however, it isn't the motive.
//                        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
//                        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
//                        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
//                        byte[] decryptedAESKeyOfServer = null;

//                        decryptedAESKeyOfServer = cipher.doFinal(EncryptedClientAES);
//                        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);

//                        int written_bytes = cipher.doFinal(EncryptedClientAES, 0, 64, decryptedAESKeyOfClient);
//                        System.out.println("Number of written bytes: " + written_bytes + "\n\n");
//                        decryptedAESKeyOfClient = cipher.doFinal(EncryptedClientAES);
//                        System.out.println(decryptedAESKeyOfClient);
                        
                        stage_count = 0; // This line resets the server to start from step 1, i.e., stage 0, again, to repeat the same procedure.
                        System.out.println("\n\nServer is resetted. Procedure can be repeated now.\n\n");
                        break;

                    default:
                        clientSocket.close();
                        break;
                }

            } catch (IOException ex) {
                System.out.println("Problem in message reading" + ex.getMessage());
            }
        }

    }

}
