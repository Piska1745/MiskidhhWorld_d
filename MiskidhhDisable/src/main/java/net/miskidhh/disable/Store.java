package net.miskidhh.disable;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Хранилище отключённых аккаунтов.
 *  - data.bin  : только соленые HMAC-хэши UUID и IP (читаемых данных там нет)
 *  - audit.enc : журнал, зашифрованный публичным ключом владельца (расшифровать может только owner.key)
 *  - salt.bin  : случайная соль для хэшей
 */
public final class Store {
    static final class Entry {
        final String id;
        final String uuidHash;
        final Set<String> ipHashes = new LinkedHashSet<>();

        Entry(String id, String uuidHash) {
            this.id = id;
            this.uuidHash = uuidHash;
        }
    }

    private final Path dataFile;
    private final Path auditFile;
    private final byte[] salt;
    private final PublicKey ownerKey;
    private final List<Entry> entries = new ArrayList<>();

    public Store(Path dir, PublicKey ownerKey) throws IOException {
        Files.createDirectories(dir);
        this.ownerKey = ownerKey;
        this.dataFile = dir.resolve("data.bin");
        this.auditFile = dir.resolve("audit.enc");
        Path saltFile = dir.resolve("salt.bin");
        if (Files.exists(saltFile)) {
            this.salt = Files.readAllBytes(saltFile);
        } else {
            this.salt = Crypto.randomBytes(32);
            Files.write(saltFile, this.salt);
        }
        load();
    }

    private String h(String v) {
        return Crypto.hmac(salt, v);
    }

    private static String clean(String s) {
        return s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
    }

    public synchronized boolean isDisabled(UUID uuid) {
        String hash = h("uuid:" + uuid);
        for (Entry e : entries) {
            if (e.uuidHash.equals(hash)) return true;
        }
        return false;
    }

    public synchronized boolean isIpBlocked(String ip) {
        String hash = h("ip:" + ip);
        for (Entry e : entries) {
            if (e.ipHashes.contains(hash)) return true;
        }
        return false;
    }

    /** Отключает аккаунт. Сначала пишет в зашифрованный журнал: нет записи в журнале - нет отключения. */
    public synchronized String disable(UUID uuid, String name, String admin, String reason, String ip) {
        String id = HexFormat.of().formatHex(Crypto.randomBytes(16));
        audit(String.join("\t", "DISABLE", Instant.now().toString(), id,
                uuid.toString(), clean(name), clean(admin), clean(reason)));
        Entry e = new Entry(id, h("uuid:" + uuid));
        if (ip != null) e.ipHashes.add(h("ip:" + ip));
        entries.add(e);
        save();
        return id;
    }

    /** Запоминает новый IP уже отключённого аккаунта. */
    public synchronized void rememberIp(UUID uuid, String ip) {
        String uh = h("uuid:" + uuid);
        String ih = h("ip:" + ip);
        for (Entry e : entries) {
            if (e.uuidHash.equals(uh)) {
                if (e.ipHashes.add(ih)) save();
                return;
            }
        }
    }

    /** Вызывается только после проверки подписи владельца. */
    public synchronized boolean removeById(String id) {
        boolean removed = entries.removeIf(e -> e.id.equals(id));
        if (removed) {
            audit(String.join("\t", "UNLOCK", Instant.now().toString(), id));
            save();
        }
        return removed;
    }

    private void audit(String line) {
        try {
            byte[] blob = Crypto.seal(ownerKey, line.getBytes(StandardCharsets.UTF_8));
            byte[] framed = ByteBuffer.allocate(4 + blob.length).putInt(blob.length).put(blob).array();
            Files.write(auditFile, framed, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void load() throws IOException {
        if (!Files.exists(dataFile)) return;
        try (DataInputStream in = new DataInputStream(new BufferedInputStream(Files.newInputStream(dataFile)))) {
            int n = in.readInt();
            for (int i = 0; i < n; i++) {
                Entry e = new Entry(in.readUTF(), in.readUTF());
                int k = in.readInt();
                for (int j = 0; j < k; j++) e.ipHashes.add(in.readUTF());
                entries.add(e);
            }
        }
    }

    private void save() {
        try {
            Path tmp = dataFile.resolveSibling("data.bin.tmp");
            try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(tmp)))) {
                out.writeInt(entries.size());
                for (Entry e : entries) {
                    out.writeUTF(e.id);
                    out.writeUTF(e.uuidHash);
                    out.writeInt(e.ipHashes.size());
                    for (String ih : e.ipHashes) out.writeUTF(ih);
                }
            }
            Files.move(tmp, dataFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
