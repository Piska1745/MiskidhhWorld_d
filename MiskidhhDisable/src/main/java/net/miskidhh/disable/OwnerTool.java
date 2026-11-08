package net.miskidhh.disable;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;

/**
 * Офлайн-инструмент владельца. Запускается НА СВОЁМ компьютере, не на сервере.
 *   genkey                          - создать пару ключей (owner.key секретный, owner.pub публичный)
 *   readlog <owner.key> <audit.enc> - расшифровать журнал
 *   unlock  <owner.key> <id записи> - создать файл разблокировки unlock-<id>.sig
 */
public final class OwnerTool {
    public static void main(String[] a) throws Exception {
        if (a.length == 0) {
            usage();
            return;
        }
        switch (a[0]) {
            case "genkey" -> {
                Path priv = Path.of("owner.key");
                Path pub = Path.of("owner.pub");
                if (Files.exists(priv) || Files.exists(pub)) {
                    System.out.println("owner.key / owner.pub уже существуют - ничего не перезаписываю.");
                    return;
                }
                KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                g.initialize(3072);
                KeyPair kp = g.generateKeyPair();
                Files.write(priv, kp.getPrivate().getEncoded());
                Files.write(pub, kp.getPublic().getEncoded());
                System.out.println("Готово. owner.key - СЕКРЕТ (хранить офлайн, не в GitHub). owner.pub - публичный.");
            }
            case "readlog" -> {
                if (a.length < 3) { usage(); return; }
                PrivateKey key = Crypto.loadPrivate(Files.readAllBytes(Path.of(a[1])));
                ByteBuffer buf = ByteBuffer.wrap(Files.readAllBytes(Path.of(a[2])));
                while (buf.remaining() >= 4) {
                    byte[] blob = new byte[buf.getInt()];
                    buf.get(blob);
                    System.out.println(new String(Crypto.open(key, blob), StandardCharsets.UTF_8));
                }
            }
            case "unlock" -> {
                if (a.length < 3) { usage(); return; }
                String id = a[2];
                if (!id.matches("[0-9a-f]{32}")) {
                    System.out.println("id записи должен быть из 32 символов a-f/0-9 (смотри readlog).");
                    return;
                }
                PrivateKey key = Crypto.loadPrivate(Files.readAllBytes(Path.of(a[1])));
                Path out = Path.of("unlock-" + id + ".sig");
                Files.write(out, Crypto.sign(key, "UNLOCK:" + id));
                System.out.println("Создан " + out + ". Положи его в plugins/MiskidhhDisable/unlock/ на сервере.");
            }
            default -> usage();
        }
    }

    private static void usage() {
        System.out.println("genkey | readlog <owner.key> <audit.enc> | unlock <owner.key> <id>");
    }
}
