<?php
require __DIR__ . '/../vendor/autoload.php';

use GuzzleHttp\Psr7\Utils;
use WhatsApp\MediaEncryption\WhatsAppEncryptionStream;

$originalPath = __DIR__ . '/AUDIO.original';

if (!file_exists($originalPath)) {
    die("Файл AUDIO.original не найден\n");
}
$plaintextStream = Utils::streamFor(file_get_contents($originalPath));

$keyPath = __DIR__ . '/AUDIO.key';

if (!file_exists($keyPath)) {
    die("Файл AUDIO.key не найден\n");
}

$mediaKey = file_get_contents($keyPath);

$mediaType = 'AUDIO';

$encryptedStream = new WhatsAppEncryptionStream($plaintextStream, $mediaKey, $mediaType);

$outputPath = __DIR__ . '/AUDIO.encrypted';

file_put_contents($outputPath, (string)$encryptedStream);

echo "Шифрование завершено. Зашифрованный файл: $outputPath\n";
