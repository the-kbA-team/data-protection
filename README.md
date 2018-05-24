# Deterministic one-way encryption of unique sensitive data

The goal of this class is to encrypt unique sensitive information, like social security numbers, without the possibility
to decrypt it afterwards but still be able to search for it using `equals` and `not equals` operators.

## Scenario

A persons data in the database contains a social security number. This kind of data is sensitive because, in case of a
security breach, a criminal can use it to assume the identities of the people stored in the breached database. Therefore
this kind of information needs to be protected.

In this scenario the social security number is never actually displayed or processed. It is used to identify a unique
person even if other stored data of that person changes over time, like a change of name in case of a marriage.

It is assumed that the social security number won't appear twice in the database.

In order to uniquely identify a person, it still has to be possible to search for the social security number, even
though this information has been encrypted. The typical search patterns are either `equals`, in case a person needs to
be uniquely identified, or `not equals` to avoid duplicate entries for the same person in the database.

Simply creating a hash value of that information, or a hash value with a static salt, won't work, because an attacker
can create a rainbow table of all possible iterations and match their hashed values against the ones stored in the
database.

Creating a salted hash value, like the ones used for passwords, won't work because it has to be possible to search a
database of thousands of entries. In order to perform an `equals` search, the information has to be hashed using all
prior used salt values. An `not equals` search in that manner won't reliably determine whether a person is _not_ in
the database.

## Solution

The solution to safely store sensitive information is to encrypt it in a deterministic way, without the possibility to
decrypt the information afterwards.

A safe encryption consists of a secret key and an initialization vector which guarantees the encrypted value is unique.

Based on the information found in [question 59580 on Stack Exchange][se59580] ciphers in CBC mode with an initialization
vector derived from the plain text match the requirement of a deterministically encrypted information.

In order to generate the same encrypted value each time, the key and the cipher algorithm used, need to stay the same
for the given database, but the key needs to be different for different databases. This will make it harder for an
attacker to create a rainbow table.

## Downfall

In case the secret encryption key is breached, the encrypted data is still safe as long as computing power doesn't allow
for a rainbow table based on all possible social security numbers encrypted with the secret key to be created within a
reasonable amount of time.

## Usage

Include this package using composer.

```bash
composer require kba-team/data-protection: "~1.0"
```

Securely generate a secret key.

```php
<?php
use kbATeam\DataProtection\SecureSearch;
//generate a key
$key_hex = SecureSearch::generateKey();
//print the result
printf('%s%s', $key_hex, PHP_EOL);
```

Encrypt the data.

```php
<?php
use kbATeam\DataProtection\SecureSearch;
//convert the key to its raw version
$key_raw = hex2bin($key_hex);
//set the social security number
$ssn = 1234567890;
//encrypt the social security number
$ssn_encrypted = SecureSearch::encrypt($ssn, $key_raw);
//print the result
printf('%s%s', $ssn_encrypted, PHP_EOL);
```

## Development

Clone repository and install all requirements using composer.

```bash
git clone https://github.com/the-kbA-team/data-protection.git
composer install
```

Run tests.

```bash
vendor/bin/phpunit --
```

## MIT License

MIT License

Copyright (c) 2018 the-kbA-team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


[se59580]: https://security.stackexchange.com/questions/59580/how-to-safely-store-sensitive-data-like-a-social-security-number#61004 "'How to safely store sensitive data like a social security number?', Retrieved 2018-05-24 09:00"
