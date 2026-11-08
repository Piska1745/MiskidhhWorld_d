# MiskidhhDisable (Paper 1.21.4, Java 21)

## Сборка в GitHub Codespaces
1. Загрузи эту папку в репозиторий GitHub и открой Codespace.
2. Сгенерируй ключи (один раз):
   mvn -q compile
   java -cp target/classes net.miskidhh.disable.OwnerTool genkey
3. Скачай owner.key к себе, спрячи офлайн и удали из Codespace. В GitHub его не коммитить (он в .gitignore).
4. Положи публичный ключ в проект: mv owner.pub src/main/resources/owner.pub
5. Собери: mvn package   ->   target/MiskidhhDisable-1.0.0.jar
6. Закинь .jar в plugins/ сервера.

## Выдача права (LuckPerms)
/lp user <ник> permission set miskidhh.disable.use true
Команда: /disableaccount <ник> <причина>. Из консоли не работает. У OP права по умолчанию нет.

## Журнал и разблокировка (только владелец ключа, на своём компьютере)
Скачай plugins/MiskidhhDisable/audit.enc и выполни:
  java -cp MiskidhhDisable-1.0.0.jar net.miskidhh.disable.OwnerTool readlog owner.key audit.enc
В строке DISABLE третье поле - id записи. Для разблокировки:
  java -cp MiskidhhDisable-1.0.0.jar net.miskidhh.disable.OwnerTool unlock owner.key <id>
Положи полученный unlock-<id>.sig в plugins/MiskidhhDisable/unlock/ - плагин проверит подпись и снимет запись в течение 30 секунд.
