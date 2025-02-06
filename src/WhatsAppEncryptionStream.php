<?php
namespace WhatsApp\MediaEncryption;

use Psr\Http\Message\StreamInterface;
use GuzzleHttp\Psr7\Utils;

/**
 * Декоратор для шифрования PSR-7 потока согласно алгоритму WhatsApp
 *
 * 1. Расширение 32-байтового mediaKey до 112 байт с помощью HKDF-SHA256 и информационной строки
 * 2. Извлечение из расширенного:
 *    - iv (16 байт)
 *    - cipherKey (32 байта)
 *    - macKey (32 байта)
 * 3. Шифрование данных с помощью AES-256-CBC
 * 4. Вычисление HMAC SHA-256 от (iv . ciphertext) с использованием macKey и использование первых 10 байт
 * 5. Итоговый поток: ciphertext . mac
 */
class WhatsAppEncryptionStream implements StreamInterface
{
    private $encryptedStream;
    
    private $mediaKey;
    
    private $mediaType;
    
    //Карта медиа
    private static $InfoMap = [
        'IMAGE'    => 'WhatsApp Image Keys',
        'VIDEO'    => 'WhatsApp Video Keys',
        'AUDIO'    => 'WhatsApp Audio Keys',
        'DOCUMENT' => 'WhatsApp Document Keys',
    ];
    
    /**
     * @param StreamInterface $plaintextStream Исходный поток с данными
     * @param string $mediaKey 32-байтовый ключ
     * @param string $mediaType Тип медиа (IMAGE, VIDEO, AUDIO, DOCUMENT)
     */
    public function __construct(StreamInterface $plaintextStream, $mediaKey, $mediaType)
    {
        $this->mediaKey = $mediaKey;
        $this->mediaType = strtoupper($mediaType);
        
        //Чтение данных
        $plaintext = $plaintextStream->getContents();
        
        //Шифрование
        $encryptedData = $this->encryptData($plaintext);
        
        //Поток для зашифрованных данных
        $this->encryptedStream = Utils::streamFor($encryptedData);
    }
    
    /**
     * @param string $plaintext Исходные данные
     * Возвращает зашифрованные данные в формате: ciphertext . mac
     */
    private function encryptData($plaintext)
    {
        $info = self::$InfoMap[$this->mediaType];
        
        //Расширение до 112 байт с помощью HKDF
        $mediaKeyExpanded = hash_hkdf('sha256', $this->mediaKey, 112, $info);
        
        $iv = substr($mediaKeyExpanded, 0, 16);
        $cipherKey = substr($mediaKeyExpanded, 16, 32);
        $macKey = substr($mediaKeyExpanded, 48, 32);
        
        // Шифрование с помощью AES-256-CBC
        $ciphertext = openssl_encrypt($plaintext, 'AES-256-CBC', $cipherKey, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new \RuntimeException('Ошибка шифрования данных');
        }
        
        $hmac = hash_hmac('sha256', $iv . $ciphertext, $macKey, true);
        $mac = substr($hmac, 0, 10);
        
        return $ciphertext . $mac;
    }
    
    
    public function __toString(): string
    {
        try {
            $this->rewind();
            return $this->encryptedStream->getContents();
        } catch (\Exception $e) {
            return '';
        }
    }
    
    public function close(): void
    {
        $this->encryptedStream->close();
    }
    
    public function detach()
    {
        return $this->encryptedStream->detach();
    }
    
    public function getSize(): int
    {
        return $this->encryptedStream->getSize();
    }
    
    public function tell(): int
    {
        return $this->encryptedStream->tell();
    }
    
    public function eof(): bool
    {
        return $this->encryptedStream->eof();
    }
    
    public function isSeekable(): bool
    {
        return $this->encryptedStream->isSeekable();
    }
    
    public function seek($offset, $whence = SEEK_SET): void
    {
        $this->encryptedStream->seek($offset, $whence);
    }
    
    public function rewind(): void
    {
        $this->encryptedStream->rewind();
    }
    
    public function isWritable(): bool
    {
        return false;
    }
    
    public function write($string): int
    {
        throw new \RuntimeException('Запись не поддерживается');
    }
    
    public function isReadable(): bool
    {
        return $this->encryptedStream->isReadable();
    }
    
    public function read($length): string
    {
        return $this->encryptedStream->read($length);
    }
    
    public function getContents(): string
    {
        return $this->encryptedStream->getContents();
    }
    
    public function getMetadata($key = null)
    {
        return $this->encryptedStream->getMetadata($key);
    }
}
