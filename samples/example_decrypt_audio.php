<?php
require __DIR__ . '/../vendor/autoload.php';

use GuzzleHttp\Psr7\Utils;
use WhatsApp\MediaEncryption\WhatsAppDecryptionStream;

$encryptedPath = __DIR__ . '/AUDIO.encrypted';

if (!file_exists($encryptedPath)) {
    die("Файл AUDIO.encrypted не найден. Сначала запустите шифрование.\n");
}

$encryptedStream = Utils::streamFor(file_get_contents($encryptedPath));

$keyPath = __DIR__ . '/AUDIO.key';

if (!file_exists($keyPath)) {
    die("Файл AUDIO.key не найден\n");
}

$mediaKey = file_get_contents($keyPath);

$mediaType = 'AUDIO';

try {

    $decryptedStream = new WhatsAppDecryptionStream($encryptedStream, $mediaKey, $mediaType);
    $outputPath = __DIR__ . '/AUDIO.decrypted';
    file_put_contents($outputPath, (string)$decryptedStream);
    
    echo "Дешифрование завершено. Расшифрованный файл: $outputPath\n";

} catch (\Exception $e) {
    echo "Ошибка при дешифровании: " . $e->getMessage() . "\n";
}
