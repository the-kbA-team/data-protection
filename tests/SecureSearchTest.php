<?php

namespace Tests\kbATeam\DataProtection;

use kbATeam\DataProtection\SecureSearch;
use PHPUnit\Framework\TestCase;

/**
 * Class Tests\kbATeam\DataProtection\SecureSearchTest
 *
 * Test the secure search class.
 *
 * @category Tests
 * @package  Tests\kbATeam\DataProtection
 * @license  MIT
 */
class SecureSearchTest extends TestCase
{
    /**
     * @const The social security number used in these tests.
     */
    const SSN = '1234567890';

    /**
     * @const Random key used to encrypt the social security number in these tests.
     */
    const KEY = '2116d1542ad7377a9395e22c8264b480cdf843b069c391ff02183179f9ff2446';

    /**
     * @const The encrypted social security number used to validate the code.
     */
    const ENCRYPTED = 'RoH2Bfuob46Mn+XX5TETBg==';

    /**
     * Assert that the same data and the same key always give the same result.
     * @return void
     */
    public function testEncryptMethodSuccessfully()
    {
        //use a fake social security number
        $data = self::SSN;
        /** @var string $key */
        $key = hex2bin(self::KEY);
        $encrypted_data = SecureSearch::encrypt($data, $key);
        $this->assertEquals(self::ENCRYPTED, $encrypted_data);
    }

    /**
     * Assert that a key of the defined length is generated.
     * @return void
     */
    public function testKeyGeneration()
    {
        $key = SecureSearch::generateKey();
        $this->assertEquals(SecureSearch::KEY_LENGTH*2, strlen($key));
    }

    /**
     * Assert that the data cannot be decrypted.
     * @return void
     */
    public function testDecryption()
    {
        $data = (int) self::SSN;
        /** @var string $key */
        $key = hex2bin(self::KEY);
        $encrypted = SecureSearch::encrypt($data, $key);
        $this->assertEquals(self::ENCRYPTED, $encrypted);
        $decrypted = openssl_decrypt($encrypted, SecureSearch::CIPHER, $key);
        $this->assertFalse($decrypted);
    }

    /**
     * Assert that it takes more than a month to calculate a rainbow table of
     * encrypted Austrian social security numbers in case the secret key has been
     * compromised.
     * @return void
     */
    public function testTimeRainbowTable()
    {
        $postfix = '010170';
        /** @var string $key */
        $key = hex2bin(self::KEY);
        $start = time();
        for ($i = 1000; $i < 1500; $i++) {
            $data = sprintf("%'.04d%s", $i, $postfix);
            SecureSearch::encrypt($data, $key);
        }
        $duration = time() - $start;
        /**
         * Multiply duration by 18, because we only calculated 500 of the 9000
         * possible prefix number for the rainbow table for a single day.
         * 2014 the average life expectancy of a human was 71.5 years. In order to
         * calculate a complete rainbow table for all possible social security
         * numbers for 72 years, we have to multiply that duration by 26.298 days.
         * The result is the number of seconds it takes a single thread to calculate
         * a complete rainbow table of all possible social security numbers of 72
         * years.
         */
        $expected_rainbow_table = $duration * 18 * 26298;
        $msg = 'This test fails, because it is possible for a single thread to'
               .' calculate a complete rainbow table of all possible social security'
               .' numbers in less than a month (30.4375 days).';
        $this->assertGreaterThan(2629800, $expected_rainbow_table, $msg);
    }
}
