<?php

declare(strict_types=1);

/**
 * Base session class.
 *
 * @package    Kohana
 * @category   Session
 * @modified   2024-07-24 - PHP 8.3 strict typing and session security enhancements
 */
abstract class Kohana_Session
{
    /**
     * @var string default session adapter
     */
    public static string $default = 'native';

    /**
     * @var array session instances
     */
    public static array $instances = [];

    /**
     * Creates a singleton session of the given type. Some session types
     * (native, database) also support restarting a session by passing a
     * session id as the second parameter.
     *
     *     $session = Session::instance();
     *
     * [!!] [Session::write] will automatically be called when the request ends.
     *
     * @param string|null $type type of session (native, cookie, etc)
     * @param string|null $id session identifier
     * @return Session
     * @uses Kohana::$config
     */
    public static function instance(?string $type = null, ?string $id = null): Session
    {
        if ($type === null) {
            // Use the default type
            $type = Session::$default;
        }

        if (!isset(Session::$instances[$type])) {
            // Load the configuration for this type
            $config = Kohana::$config->load('session')->get($type);

            // Set the session class name
            $class = 'Session_' . ucfirst($type);

            // Create a new session instance
            Session::$instances[$type] = $session = new $class($config, $id);

            // Write the session at shutdown
            register_shutdown_function([$session, 'write']);
        }

        return Session::$instances[$type];
    }

    /**
     * @var string cookie name
     */
    protected string $_name = 'session';

    /**
     * @var int cookie lifetime
     */
    protected int $_lifetime = 0;

    /**
     * @var bool encrypt session data?
     */
    protected bool $_encrypted = false;

    /**
     * @var array session data
     */
    protected array $_data = [];

    /**
     * @var bool session destroyed?
     */
    protected bool $_destroyed = false;

    /**
     * Overloads the name, lifetime, and encrypted session settings.
     *
     * [!!] Sessions can only be created using the [Session::instance] method.
     *
     * @param array|null $config configuration
     * @param string|null $id session id
     * @return void
     * @uses Session::read
     */
    public function __construct(array $config = null, ?string $id = null)
    {
        if (isset($config['name'])) {
            // Cookie name to store the session id in
            $this->_name = (string) $config['name'];
        }

        if (isset($config['lifetime'])) {
            // Cookie lifetime
            $this->_lifetime = (int) $config['lifetime'];
        }

        if (isset($config['encrypted'])) {
            if ($config['encrypted'] === true) {
                // Use the default Encrypt instance
                $config['encrypted'] = 'default';
            }

            // Enable or disable encryption of data
            $this->_encrypted = (bool) $config['encrypted'];
        }

        // Load the session
        $this->read($id);
    }

    /**
     * Session object is rendered to a serialized string. If encryption is
     * enabled, the session will be encrypted. If not, the output string will
     * be encoded.
     *
     * @return string
     * @uses Encrypt::encode
     */
    public function __toString(): string
    {
        // Serialize the data array
        $data = $this->_serialize($this->_data);

        if ($this->_encrypted) {
            // Generate a new encryption key for this session
            $key = $this->_generate_encryption_key();
            $_SESSION['_encryption_key'] = $key;

            // Encrypt the data using the generated key
            $data = $this->_encrypt($data, $key);
        } else {
            // Encode the data
            $data = $this->_encode($data);
        }

        return $data;
    }

    /**
     * Returns the current session array. The returned array can also be
     * assigned by reference.
     *
     * @return array
     */
    public function &as_array(): array
    {
        return $this->_data;
    }

    /**
     * Get the current session id, if the session supports it.
     *
     * @return string|null
     */
    public function id(): ?string
    {
        return null;
    }

    /**
     * Get the current session cookie name.
     *
     * @return string
     */
    public function name(): string
    {
        return $this->_name;
    }

    /**
     * Get a variable from the session array.
     *
     * @param string $key variable name
     * @param mixed $default default value to return
     * @return mixed
     */
    public function get(string $key, $default = null)
    {
        return array_key_exists($key, $this->_data) ? $this->_data[$key] : $default;
    }

    /**
     * Get and delete a variable from the session array.
     *
     * @param string $key variable name
     * @param mixed $default default value to return
     * @return mixed
     */
    public function get_once(string $key, $default = null)
    {
        $value = $this->get($key, $default);
        unset($this->_data[$key]);
        return $value;
    }

    /**
     * Set a variable in the session array.
     *
     * @param string $key variable name
     * @param mixed $value value
     * @return $this
     */
    public function set(string $key, $value): self
    {
        $this->_data[$key] = $value;
        return $this;
    }

    /**
     * Set a variable by reference.
     *
     * @param string $key variable name
     * @param mixed $value referenced value
     * @return $this
     */
    public function bind(string $key, &$value): self
    {
        $this->_data[$key] = &$value;
        return $this;
    }

    /**
     * Removes a variable in the session array.
     *
     * @param string ...$keys variable names
     * @return $this
     */
    public function delete(string ...$keys): self
    {
        foreach ($keys as $key) {
            unset($this->_data[$key]);
        }
        return $this;
    }

    /**
     * Loads existing session data.
     *
     * @param string|null $id session id
     * @return void
     */
    public function read(?string $id = null): void
    {
        $data = null;

        try {
            if (is_string($data = $this->_read($id))) {
                if ($this->_encrypted) {
                    // Decrypt the data using the stored key
                    $key = $_SESSION['_encryption_key'] ?? null;
                    if ($key) {
                        $data = $this->_decrypt($data, $key);
                    }
                } else {
                    // Decode the data
                    $data = $this->_decode($data);
                }

                // Unserialize the data
                $data = $this->_unserialize($data);
            } else {
                // Ignore these, session is valid, likely no data though.
            }
        } catch (Exception $e) {
            // Error reading the session, usually a corrupt session.
            throw new Session_Exception('Error reading session data.', 0, $e);
        }

        if (is_array($data)) {
            // Load the data locally
            $this->_data = $data;
        }
    }

    /**
     * Generates a new session id and returns it.
     *
     * @return string
     */
    public function regenerate(): string
    {
        return $this->_regenerate();
    }

    /**
     * Sets the last_active timestamp and saves the session.
     *
     * @return bool
     * @uses Kohana::$log
     */
    public function write(): bool
    {
        if (headers_sent() || $this->_destroyed) {
            // Session cannot be written when the headers are sent or when
            // the session has been destroyed
            return false;
        }

        // Set the last active timestamp
        $this->_data['last_active'] = time();

        try {
            return $this->_write();
        } catch (Exception $e) {
            // Log & ignore all errors when a write fails
            Kohana::$log->add(Log::ERROR, Kohana_Exception::text($e))->write();
            return false;
        }
    }

    /**
     * Completely destroy the current session.
     *
     * @return bool
     */
    public function destroy(): bool
    {
        if ($this->_destroyed === false) {
            if ($this->_destroyed = $this->_destroy()) {
                // The session has been destroyed, clear all data
                $this->_data = [];
            }
        }

        return $this->_destroyed;
    }

    /**
     * Restart the session.
     *
     * @return bool
     */
    public function restart(): bool
    {
        if ($this->_destroyed === false) {
            // Wipe out the current session.
            $this->destroy();
        }

        // Allow the new session to be saved
        $this->_destroyed = false;

        return $this->_restart();
    }

    /**
     * Serializes the session data.
     *
     * @param array $data data
     * @return string
     */
    protected function _serialize(array $data): string
    {
        return serialize($data);
    }

    /**
     * Unserializes the session data.
     *
     * @param string $data data
     * @return array
     */
    protected function _unserialize(string $data): array
    {
        return unserialize($data);
    }

    /**
     * Encodes the session data using [base64_encode].
     *
     * @param string $data data
     * @return string
     */
    protected function _encode(string $data): string
    {
        return base64_encode($data);
    }

    /**
     * Decodes the session data using [base64_decode].
     *
     * @param string $data data
     * @return string
     */
    protected function _decode(string $data): string
    {
        return base64_decode($data);
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

    /**
     * Loads the raw session data string and returns it.
     *
     * @param string|null $id session id
     * @return string|null
     */
    abstract protected function _read(?string $id = null): ?string;

    /**
     * Generate a new session id and return it.
     *
     * @return string
     */
    abstract protected function _regenerate(): string;

    /**
     * Writes the current session.
     *
     * @return bool
     */
    abstract protected function _write(): bool;

    /**
     * Destroys the current session.
     *
     * @return bool
     */
    abstract protected function _destroy(): bool;

    /**
     * Restarts the current session.
     *
     * @return bool
     */
    abstract protected function _restart(): bool;
}
