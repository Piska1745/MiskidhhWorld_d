package net.miskidhh.disable;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;
import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.InputStream;
import java.net.InetAddress;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.UUID;

public final class DisablePlugin extends JavaPlugin implements Listener, CommandExecutor {
    private static final String SERVER_NAME = "MiskidhhWorld";
    private static final String PERMISSION = "miskidhh.disable.use";

    private Store store;
    private PublicKey ownerKey;

    @Override
    public void onEnable() {
        try {
            try (InputStream in = getResource("owner.pub")) {
                if (in == null) {
                    throw new IllegalStateException("В .jar нет owner.pub - см. README, шаг с генерацией ключа");
                }
                ownerKey = Crypto.loadPublic(in.readAllBytes());
            }
            store = new Store(getDataFolder().toPath(), ownerKey);
            Files.createDirectories(getDataFolder().toPath().resolve("unlock"));
        } catch (Exception e) {
            getLogger().severe("Не удалось запуститься: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        getServer().getPluginManager().registerEvents(this, this);
        getCommand("disableaccount").setExecutor(this);
        // Раз в 30 секунд ищем подписанные владельцем файлы разблокировки.
        getServer().getScheduler().runTaskTimerAsynchronously(this, this::processUnlocks, 100L, 600L);
    }

    // ---------- команда ----------

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        // Консоль, RCON и командные блоки не могут отключать аккаунты - только игрок с правом.
        if (!(sender instanceof Player admin)) {
            sender.sendMessage("Отключать аккаунты можно только в игре и только с отдельным правом.");
            return true;
        }
        if (!admin.hasPermission(PERMISSION)) {
            admin.sendMessage(Component.text("Недостаточно прав.", NamedTextColor.RED));
            return true;
        }
        if (args.length < 2) {
            admin.sendMessage(Component.text("Использование: /disableaccount <ник> <причина>", NamedTextColor.RED));
            return true;
        }

        String targetName = args[0];
        String reason = String.join(" ", Arrays.copyOfRange(args, 1, args.length));
        if (reason.length() > 200) reason = reason.substring(0, 200);

        Player online = Bukkit.getPlayerExact(targetName);
        OfflinePlayer target = online != null ? online : Bukkit.getOfflinePlayerIfCached(targetName);
        if (target == null) {
            admin.sendMessage(Component.text("Игрок не найден (он должен был хотя бы раз зайти на сервер).",
                    NamedTextColor.RED));
            return true;
        }
        UUID uuid = target.getUniqueId();
        if (uuid.equals(admin.getUniqueId())) {
            admin.sendMessage(Component.text("Нельзя отключить свой собственный аккаунт.", NamedTextColor.RED));
            return true;
        }
        if (store.isDisabled(uuid)) {
            admin.sendMessage(Component.text("Этот аккаунт уже отключён.", NamedTextColor.RED));
            return true;
        }

        String shownName = target.getName() != null ? target.getName() : targetName;
        String ip = online != null && online.getAddress() != null ? ipOf(online.getAddress().getAddress()) : null;

        try {
            store.disable(uuid, shownName, admin.getName(), reason, ip);
        } catch (RuntimeException e) {
            getLogger().severe("Ошибка при отключении аккаунта: " + e.getMessage());
            admin.sendMessage(Component.text("Ошибка записи. Аккаунт НЕ отключён.", NamedTextColor.RED));
            return true;
        }

        Component msg = Component.text("Аккаунт игрока ", NamedTextColor.RED)
                .append(Component.text(shownName, NamedTextColor.YELLOW))
                .append(Component.text(" был отключён администратором ", NamedTextColor.RED))
                .append(Component.text(admin.getName(), NamedTextColor.YELLOW))
                .append(Component.text(" по причине: ", NamedTextColor.RED))
                .append(Component.text(reason, NamedTextColor.WHITE))
                .append(Component.text(". Возврат аккаунта только через систему.", NamedTextColor.RED));
        Bukkit.getServer().broadcast(msg);

        if (online != null) online.kick(kickMessage());
        return true;
    }

    // ---------- вход на сервер ----------

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent e) {
        String ip = ipOf(e.getAddress());
        UUID uuid = e.getUniqueId();
        boolean blocked = store.isDisabled(uuid);
        if (blocked) {
            if (ip != null) store.rememberIp(uuid, ip);
        } else if (ip != null && store.isIpBlocked(ip)) {
            blocked = true;
        }
        if (blocked) e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, kickMessage());
    }

    // Второй рубеж: на случай, если другой плагин попытается пропустить игрока обратно.
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onLogin(PlayerLoginEvent e) {
        String ip = ipOf(e.getAddress());
        if (store.isDisabled(e.getPlayer().getUniqueId()) || (ip != null && store.isIpBlocked(ip))) {
            e.disallow(PlayerLoginEvent.Result.KICK_BANNED, kickMessage());
        }
    }

    // ---------- разблокировка только подписью владельца ----------

    private void processUnlocks() {
        Path dir = getDataFolder().toPath().resolve("unlock");
        if (!Files.isDirectory(dir)) return;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "unlock-*.sig")) {
            for (Path p : ds) {
                String name = p.getFileName().toString();
                String id = name.substring("unlock-".length(), name.length() - ".sig".length());
                try {
                    boolean valid = id.matches("[0-9a-f]{32}")
                            && Crypto.verify(ownerKey, "UNLOCK:" + id, Files.readAllBytes(p));
                    if (valid && store.removeById(id)) {
                        getLogger().info("Применена подпись владельца: запись " + id + " снята.");
                    } else if (!valid) {
                        getLogger().warning("Файл " + name + " с неверной подписью удалён.");
                    }
                    Files.deleteIfExists(p);
                } catch (Exception ex) {
                    getLogger().warning("Не удалось обработать " + name + ": " + ex.getMessage());
                }
            }
        } catch (Exception ex) {
            getLogger().warning("Ошибка чтения папки unlock: " + ex.getMessage());
        }
    }

    // ---------- вспомогательное ----------

    private Component kickMessage() {
        return Component.text(SERVER_NAME, NamedTextColor.GOLD, TextDecoration.BOLD)
                .append(Component.newline()).append(Component.newline())
                .append(Component.text("Ваш аккаунт был отключён администрацией сервера.", NamedTextColor.RED))
                .append(Component.newline())
                .append(Component.text("Возврат аккаунта невозможен.", NamedTextColor.RED));
    }

    /** null для локальных адресов, чтобы случайно не заблокировать прокси/localhost. */
    private static String ipOf(InetAddress a) {
        if (a == null || a.isLoopbackAddress() || a.isAnyLocalAddress()) return null;
        return a.getHostAddress();
    }
}
