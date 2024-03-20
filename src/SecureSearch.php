<?php

namespace kbATeam\DataProtection;

use RuntimeException;

/**
 * Class kbATeam\DataProtection\SecureSearch
 *
 * Deterministic one-way encryption of unique sensitive data.
 * See README.md for details!
 *
 * The code surrounded by codeCoverageIgnore tags is not supposed to be reached,
 * except when it happens (e.g. in the unlikely event openssl doesn't know the cipher
 * being used) you'd want to know what happened where and to stop and further
 * execution.
 *
 * @category library
 * @package  kbATeam\DataProtection
 * @license  MIT
 */
class SecureSearch
{
    /**
     * @const Encryption method used to encrypt the data.
     *        Only CBC based ciphers are applicable here! See README.md for details.
     */
    const CIPHER = 'AES-256-CBC';

    /**
     * @const Hash method used for the IV derivation.
     */
    const HASH = 'SHA256';

    /**
     * @const Number of iterations for the Password-Based Key Derivation Function.
     */
    const PBKDF2_ITERATIONS = 64000;

    /**
     * @const Length of the key generated.
     */
    const KEY_LENGTH = 32;

    /**
     * One-way encryption of unique sensitive data.
     *
     * @param string $data The data to encrypt.
     * @param string $key  The key to use for encryption.
     * @return string The base64 encoded encrypted data.
     * @throws \RuntimeException in case the determination of the IV length,
     *              the IV derivation from the data, or the encryption fails.
     */
    public static function encrypt($data, $key): string
    {
        /**
         * Determine the length of the initialization vector for the given cipher.
         */
        $iv_length = openssl_cipher_iv_length(self::CIPHER);
        /**
         * Throw exception in case the IV length cannot be determined.
         * Are you messing with the cipher used?
         */
        if (false === $iv_length) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('error determining IV length for cipher');
            //@codeCoverageIgnoreEnd
        }
        /**
         * Use the hash of the key as salt for the IV creation.
         * This can be anything as long as it's deterministic.
         */
        $salt = hash(self::HASH, $key);

        /**
         * Derive the initialization vector from the given data.
         * Attention: binary content.
         */
        $iv = openssl_pbkdf2($data, $salt, $iv_length, self::PBKDF2_ITERATIONS, self::HASH);
        /**
         * Throw exception in case the IV derivation from the plain text failed.
         */
        if (false === $iv) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('IV derivation from data failed');
            //@codeCoverageIgnoreEnd
        }
        /**
         * Encrypt the data.
         * Options "0" means, that the result is base64 encoded.
         */
        $result = openssl_encrypt($data, self::CIPHER, $key, 0, $iv);
        if (false === $result) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('encryption of data failed');
            //@codeCoverageIgnoreEnd
        }
        /**
         * Make sure the contents of these variables isn't accessible anymore because
         * they contain sensitive information that can compromise the security of the
         * encryption.
         */
        $key_hash = $iv_length = $iv = '';
        unset($key_hash, $iv_length, $iv);

        return $result;
    }

    /**
     * Generate a key for encryption.
     *
     * @return string Hexadecimal representation of the generated key.
     * @throws \RuntimeException in case the key length is too weak or the key
     *                           generation failed.
     */
    public static function generateKey(): string
    {
        /**
         * Generate a secret key based on the defined key length.
         */
        $key_raw = openssl_random_pseudo_bytes(self::KEY_LENGTH, $is_strong);
        /**
         * Throw exception in case the random key generation failed.
         */
        if (true !== $is_strong || false == $key_raw) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('key generation failed');
            //@codeCoverageIgnoreEnd
        }
        return bin2hex($key_raw);
    }
}
