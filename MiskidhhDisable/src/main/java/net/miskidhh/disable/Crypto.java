package net.miskidhh.disable;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;

/** Вся криптография в одном месте. Не зависит от Bukkit, поэтому работает и в OwnerTool. */
public final class Crypto {
    private static final SecureRandom RNG = new SecureRandom();
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private Crypto() {}

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public static String hmac(byte[] key, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static PublicKey loadPublic(byte[] der) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    public static PrivateKey loadPrivate(byte[] der) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    /** Гибридное шифрование: случайный AES-ключ шифрует данные, RSA публичным ключом шифрует AES-ключ. */
    public static byte[] seal(PublicKey pub, byte[] plain) throws GeneralSecurityException {
        byte[] aes = randomBytes(32);
        byte[] iv = randomBytes(12);

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, pub, OAEP);
        byte[] wrapped = rsa.doFinal(aes);

        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = gcm.doFinal(plain);

        return ByteBuffer.allocate(2 + wrapped.length + iv.length + ct.length)
                .putShort((short) wrapped.length).put(wrapped).put(iv).put(ct).array();
    }

    public static byte[] open(PrivateKey priv, byte[] blob) throws GeneralSecurityException {
        ByteBuffer buf = ByteBuffer.wrap(blob);
        byte[] wrapped = new byte[buf.getShort() & 0xFFFF];
        buf.get(wrapped);
        byte[] iv = new byte[12];
        buf.get(iv);
        byte[] ct = new byte[buf.remaining()];
        buf.get(ct);

        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.DECRYPT_MODE, priv, OAEP);
        byte[] aes = rsa.doFinal(wrapped);

        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes, "AES"), new GCMParameterSpec(128, iv));
        return gcm.doFinal(ct);
    }

    public static byte[] sign(PrivateKey priv, String msg) throws GeneralSecurityException {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(priv);
        s.update(msg.getBytes(StandardCharsets.UTF_8));
        return s.sign();
    }

    public static boolean verify(PublicKey pub, String msg, byte[] sig) {
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initVerify(pub);
            s.update(msg.getBytes(StandardCharsets.UTF_8));
            return s.verify(sig);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
