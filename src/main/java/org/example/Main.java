package org.example;

import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.GenerateMacRequest;
import com.amazonaws.services.kms.model.GenerateMacResult;
import netscape.javascript.JSObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {

        System.out.println("Hello world!");
        getPublicKeyFromAws();
    }

    private static PublicKey getPublicKeyFromAws() {
        PublicKey publicKey = null;
        try {
            final URL url = new URL("https://jm2s2z3umj.execute-api.us-east-1.amazonaws.com/Prod/shortribsauze");
            final HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer content = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }

            JSONObject jsonObject = new JSONObject(content.toString());
            final String shortRibSauceStr = jsonObject.getString("shortRibSauce");
            System.out.println(shortRibSauceStr);
            final byte[] shortRibSauce = Base64.getDecoder().decode(shortRibSauceStr.getBytes());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(shortRibSauce));
            in.close();

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        return publicKey;
    }

    public String encryptMac(final String stMessage) {
        byte[] macBytes;
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("OAEP", new BouncyCastleProvider());
            AlgorithmParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            parameters.init(spec);
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKeyFromAws(), parameters);
            macBytes = cipher.doFinal(stMessage.getBytes());
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException | NoSuchPaddingException |
                 InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }

        return Base64.getEncoder().encodeToString(macBytes);
    }

    public String generateMac(final String stMessage) {
        final AWSKMS kms = AWSKMSClientBuilder.standard().withCredentials(new ProfileCredentialsProvider("macNcheese")).build();;
        final ByteBuffer mac = ByteBuffer.wrap(Base64.getEncoder().encode(stMessage.getBytes()));
        final GenerateMacRequest macRequest = new GenerateMacRequest().withKeyId("alias/macNcheeseIceCream").withMacAlgorithm("HMAC_SHA_256").withMessage(mac);
        final GenerateMacResult genMacResult = kms.generateMac(macRequest);
        final ByteBuffer base64Mac = genMacResult.getMac();
        System.out.println("Generated Mac" + Base64.getEncoder().encodeToString(base64Mac.array()));
        return Base64.getEncoder().encodeToString(base64Mac.array());
    }
}