<?php
namespace WhatsApp\MediaEncryption;

use Psr\Http\Message\StreamInterface;
use GuzzleHttp\Psr7\Utils;

/**
 * Декоратор для дешифрования потока по алгоритму WhatsApp
 *
 * Алгоритм обратен шифрованию:
 * 1. Чтение всего зашифрованный потока
 * 2. Расширение mediaKey до 112 байт с помощью HKDF-SHA256 и соответствующей информационной строки
 * 3. Из mediaKeyExpanded извлекается iv, cipherKey и macKey
 * 4. Разбивка входящих данных: последние 10 байт – это mac, остальное – ciphertext
 * 5. Вычисление HMAC SHA‑256 от (iv . ciphertext) и сравнение первых 10 байт с полученным mac
 * 6. Если проверка пройдена, идет дешифровка ciphertext с помощью AES‑256‑CBC
 */
class WhatsAppDecryptionStream implements StreamInterface
{
    private $decryptedStream;

    private $mediaKey;

    private $mediaType;

    //Карта медиа
    private static $infoMap = [
        'IMAGE'    => 'WhatsApp Image Keys',
        'VIDEO'    => 'WhatsApp Video Keys',
        'AUDIO'    => 'WhatsApp Audio Keys',
        'DOCUMENT' => 'WhatsApp Document Keys',
    ];

    /**
     * @param StreamInterface $encryptedStream Поток с зашифрованными данными
     * @param string $mediaKey 32-байтовый ключ
     * @param string $mediaType Тип медиа (IMAGE, VIDEO, AUDIO, DOCUMENT)
     */
    public function __construct(StreamInterface $encryptedStream, $mediaKey, $mediaType)
    {
        $this->mediaKey = $mediaKey;
        $this->mediaType = strtoupper($mediaType);

        //Чтение данных
        $encryptedData = $encryptedStream->getContents();

        //Дешифровка
        $plaintext = $this->decryptData($encryptedData);

        //Поток с расшифрованными данными
        $this->decryptedStream = Utils::streamFor($plaintext);
    }

    /**
     * @param string $encryptedData Данные в формате: ciphertext . mac
     * Возвращает расшифрованные данные
     */
    private function decryptData($encryptedData)
    {
        $info = self::$infoMap[$this->mediaType];

        //Расширяем mediaKey до 112 байт
        $mediaKeyExpanded = hash_hkdf('sha256', $this->mediaKey, 112, $info);

        $iv = substr($mediaKeyExpanded, 0, 16);
        $cipherKey = substr($mediaKeyExpanded, 16, 32);
        $macKey = substr($mediaKeyExpanded, 48, 32);

        //Проверяем, что зашифрованных данных достаточно для наличия mac (10 байт)
        if (strlen($encryptedData) < 10) {
            throw new \RuntimeException('Неверный формат зашифрованных данных');
        }

        //Извлечение данных ciphertext и mac
        $macProvided = substr($encryptedData, -10);
        $ciphertext = substr($encryptedData, 0, -10);

        $expectedMac = substr(hash_hmac('sha256', $iv . $ciphertext, $macKey, true), 0, 10);

        if (!hash_equals($expectedMac, $macProvided)) {
            throw new \RuntimeException('MAC не соответствует – ошибка в данных');
        }

        //Расшифровка ciphertext с помощью AES-256-CBC
        $plaintext = openssl_decrypt($ciphertext, 'AES-256-CBC', $cipherKey, OPENSSL_RAW_DATA, $iv);

        if ($plaintext === false) {
            throw new \RuntimeException('Ошибка дешифрования данных');
        }

        return $plaintext;
    }


    public function __toString(): string
    {
        try {
            $this->rewind();
            return $this->decryptedStream->getContents();
        } catch (\Exception $e) {
            return '';
        }
    }

    public function close(): void
    {
        $this->decryptedStream->close();
    }

    public function detach()
    {
        return $this->decryptedStream->detach();
    }

    public function getSize(): int
    {
        return $this->decryptedStream->getSize();
    }

    public function tell(): int
    {
        return $this->decryptedStream->tell();
    }

    public function eof(): bool
    {
        return $this->decryptedStream->eof();
    }

    public function isSeekable(): bool
    {
        return $this->decryptedStream->isSeekable();
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        $this->decryptedStream->seek($offset, $whence);
    }

    public function rewind(): void
    {
        $this->decryptedStream->rewind();
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write($string): int
    {
        throw new \RuntimeException('Запись не поддерживается в расшифрованном потоке.');
    }

    public function isReadable(): bool
    {
        return $this->decryptedStream->isReadable();
    }

    public function read($length): string
    {
        return $this->decryptedStream->read($length);
    }

    public function getContents(): string
    {
        return $this->decryptedStream->getContents();
    }

    public function getMetadata($key = null)
    {
        return $this->decryptedStream->getMetadata($key);
    }
}
