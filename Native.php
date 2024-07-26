<?php

declare(strict_types=1);

/**
 * Native session class.
 *
 * @package    Kohana
 * @category   Cookie
 * @modified   2024-07-24 - PHP 8.3 strict typing and Cookie
 */
class Kohana_Session_Native extends Session
{
    public function id(): string
    {
        return session_id();
    }

    protected function _read(?string $id = null): ?string
{
    // Настройки параметров куки для сессии
    session_set_cookie_params([
        'lifetime' => $this->_lifetime,
        'path' => Cookie::$path,
        'domain' => Cookie::$domain,
        'secure' => Cookie::$secure,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    session_name($this->_name);

    if ($id !== null) {
        session_id($id);
    }

    // Запуск сессии с дополнительными параметрами безопасности
    session_start([
        'use_strict_mode' => true,
        'sid_length' => 48,
        'sid_bits_per_character' => 6,
        'cache_limiter' => ''
    ]);

    // Проверка подлинности сессии и регенерация, если необходимо
    if (!$this->_validate_session()) {
        $this->regenerate();
        $_SESSION = [];
    } elseif ($this->_should_regenerate()) {
        $this->regenerate();
    }

    // Чтение данных сессии
    $this->_data = $_SESSION;

    return null;
}

protected function _write(): bool
{
    if ($this->_destroyed) {
        return false;
    }

    // Установить время последней активности
    $this->_data['last_active'] = time();

    // Записываем данные напрямую в $_SESSION
    $_SESSION = $this->_data;

    return session_write_close();
}

    protected function _regenerate(): string
    {
        session_regenerate_id(true);
        return session_id();
    }

    public function regenerate(): string
    {
        $_SESSION['_last_regenerate'] = time();
        session_regenerate_id(true);
        return session_id();
    }

    protected function _restart(): bool
    {
        $status = session_start([
            'use_strict_mode' => true,
            'sid_length' => 48,
            'sid_bits_per_character' => 6,
            'cache_limiter' => ''
        ]);
        $this->_data = &$_SESSION;
        return $status;
    }

    protected function _destroy(): bool
    {
        // Удаляем все данные из сессии
        $_SESSION = [];

        // Получаем параметры куки для текущей сессии
        $params = session_get_cookie_params();

        // Удаляем сессионные куки, устанавливая срок их действия в прошлое
        setcookie($this->_name, '', time() - 42000,
            $params['path'], $params['domain'],
            $params['secure'], $params['httponly']
        );

        // Разрушаем сессию
        session_destroy();

        // Проверяем, что сессия действительно уничтожена
        $status = session_id() === '';

        if ($status) {
            // Удаляем соответствующий куки
            Cookie::delete($this->_name);
        }

        return $status;
    }

    private function _should_regenerate(): bool
    {
        return !isset($_SESSION['_last_regenerate']) ||
               (time() - $_SESSION['_last_regenerate']) > 900; // 15 минут
    }

    private function _validate_session(): bool
    {
        // Если сессия только что создана, инициализируем отпечаток и время создания
        if (!isset($_SESSION['_created'])) {
            $_SESSION['_created'] = time();
            $_SESSION['_fingerprint'] = $this->_generate_fingerprint();
        }

        // Проверяем отпечаток сессии
        if ($_SESSION['_fingerprint'] !== $this->_generate_fingerprint()) {
            return false;
        }

        // Обновляем отпечаток сессии
        $_SESSION['_fingerprint'] = $this->_generate_fingerprint();
        return true;
    }

    private function _generate_fingerprint(): string
    {
        return hash('sha256', 
            $_SERVER['HTTP_USER_AGENT'] . 
            (ip2long($_SERVER['REMOTE_ADDR']) & ip2long('255.255.0.0'))
        );
    }

    /**
     * Encrypts the data using the given key.
     *
     * @param string $data data to encrypt
     * @param string $key encryption key
     * @return string
     */
    protected function _encrypt(string $data, string $key): string
    {
        $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypts the data using the given key.
     *
     * @param string $data data to decrypt
     * @param string $key decryption key
     * @return string
     */
    protected function _decrypt(string $data, string $key): string
    {
        $data = base64_decode($data);
        $iv = substr($data, 0, openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = substr($data, openssl_cipher_iv_length('aes-256-cbc'));
        return openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
    }

    /**
     * Generates a new encryption key.
     *
     * @return string
     */
    protected function _generate_encryption_key(): string
    {
        return bin2hex(random_bytes(32));
    }
}
