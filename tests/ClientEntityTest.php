<?php

namespace IanSimpson\Tests;

use IanSimpson\OAuth2\Entities\ClientEntity;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationException;

/**
 * @internal
 */
class ClientEntityTest extends SapphireTest
{
    protected $usesDatabase = true;

    public function testRedirectUriRequired(): void
    {
        $this->expectException(ValidationException::class);

        $e = new ClientEntity();
        $e->populateDefaults();
        $e->write();
    }

    public function testRedirectUriWhitespace(): void
    {
        $this->expectException(ValidationException::class);

        $e = new ClientEntity();
        $e->populateDefaults();
        $e->ClientRedirectUri = ' ';
        $e->write();
    }

    public function testValidatePass(): void
    {
        $e = new ClientEntity();
        $e->populateDefaults();
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->write();
    }

    public function testLegacySecretMigratesToHashed(): void
    {
        $e                    = new ClientEntity();
        $e->ClientIdentifier  = '123';
        $e->ClientSecret      = 'abc';
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->write();

        $this->assertTrue(empty($e->ClientSecret));
        $this->assertTrue($e->isSecretValid('abc'));
    }

    public function testSecretWorks(): void
    {
        $e                    = new ClientEntity();
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->populateDefaults();

        $secret = $e->HashedClientSecret;

        $e->write();

        $this->assertNotEquals($secret, $e->HashedClientSecret);
        $this->assertTrue(empty($e->ClientSecret));
        $this->assertTrue($e->isSecretValid($secret));
    }

    public function testSecretIsNotAvailableAfterWriting(): void
    {
        $e                    = new ClientEntity();
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->populateDefaults();
        $e->write();

        $refreshed   = ClientEntity::get()->byID($e->ID);
        $secretField = $refreshed->getCMSFields()->fieldByName('Root.Main.HashedClientSecret');
        $this->assertNull($secretField);
        $hiddenSecret = $refreshed->getCMSFields()->fieldByName('Root.Main.HiddenHashedClientSecret')->Value();
        $this->assertEquals($hiddenSecret, '<hidden>');
    }

    public function testLegacyWarningIsShown(): void
    {
        $e                    = new ClientEntity();
        $e->ClientIdentifier  = '123';
        $e->ClientSecret      = 'abc';
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';

        $secret = $e->getCMSFields()->fieldByName('Root.Main.HashedClientSecret');
        $this->assertNull($secret);
        $legacyField = $e->getCMSFields()->fieldByName('Root.Main.LegacyClientSecret');
        $this->assertNotNull($legacyField);
    }
}
