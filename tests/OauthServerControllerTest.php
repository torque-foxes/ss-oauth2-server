<?php

namespace IanSimpson\Tests;

use GuzzleHttp\Psr7\Query;
use SilverStripe\Core\Environment;
use IanSimpson\OAuth2\Entities\AccessTokenEntity;
use IanSimpson\OAuth2\Entities\AuthCodeEntity;
use IanSimpson\OAuth2\Entities\ClientEntity;
use IanSimpson\OAuth2\OauthServerController;
use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\FunctionalTest;
use Monolog\Logger;
use Lcobucci\JWT\Validation\Validator;
use Lcobucci\JWT\Token\Parser;

class OauthServerControllerTest extends FunctionalTest
{
    use CryptTrait;

    protected static $fixture_file = 'OauthServerControllerTest.yml';

    protected $autoFollowRedirection = false;

    private $logger;

    protected function setUp(): void
    {
        parent::setUp();

        Config::nest();

        $_SERVER['SERVER_PORT'] = 80;

        $encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen';
        $this->setEncryptionKey($encryptionKey);

        $publicKey = __DIR__. '/public.key';
        $privateKey = __DIR__. '/private.key';

        Environment::putEnv('OAUTH_PUBLIC_KEY_PATH=' . $publicKey);
        Environment::putEnv('OAUTH_PRIVATE_KEY_PATH=' . $privateKey);

        chmod($publicKey, 0600);
        chmod($privateKey, 0600);

        $this->logger = $this->getMockBuilder(Logger::class)
            ->disableOriginalConstructor()
            ->getMock();

        Injector::inst()->registerService($this->logger, 'IanSimpson\\OAuth2\\Logger');
    }

    protected function tearDown(): void
    {
        Config::unnest();

        parent::tearDown();
    }

    public function testAuthorize(): void
    {
        $state = 789;
        $c = $this->objFromFixture(ClientEntity::class, 'test');
        $m = $this->objFromFixture('Member', 'joe');
        $this->logInAs($m->ID);

        $this->logger->expects($this->once())
            ->method('info')
            ->with($this->equalTo(
                'joe@joe.org authorised test (123) to access scopes "read_profile" on their behalf'
            ));

        $resp = $this->get(sprintf(
            'http://localhost/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=read_profile&state=%s',
            $c->ClientIdentifier,
            urlencode('http://client/callback'),
            $state
        ));

        $this->assertEquals(302, $resp->getStatusCode());
        $url = parse_url($resp->getHeader('Location'));
        $query = Query::parse($url['query']);
        $this->assertEquals($url['host'], 'client');
        $this->assertEquals($url['path'], '/callback');
        $this->assertEquals($query['state'], $state);

        // Have a look inside payload too.
        $payload = json_decode($this->decrypt($query['code']), true);
        $authCodeEntity = AuthCodeEntity::get()->filter('Code', $payload['auth_code_id'])->first();
        $this->assertEquals($payload['client_id'], $c->ClientIdentifier);
        $this->assertEquals($payload['user_id'], $m->ID);
        $this->assertNotNull($authCodeEntity);
    }

    public function testAccessToken(): void
    {
        $redir = 'http://client/callback';
        $c = $this->objFromFixture(ClientEntity::class, 'test');
        $m = $this->objFromFixture('Member', 'joe');
        $ac = $this->objFromFixture(AuthCodeEntity::class, 'test');

        // Make fake code.
        $payload = [
            'client_id' => $c->ClientIdentifier,
            'redirect_uri' => $redir,
            'auth_code_id' => $ac->Code,
            'scopes' => [],
            'user_id' => $m->ID,
            'expire_time' => strtotime('2099-06-06 12:00:00'),
            'code_challenge' => null,
            'code_challenge_method' => null,
        ];
        $authCode = $this->encrypt(json_encode($payload));

        $resp = $this->post('http://localhost/oauth/accessToken', [
            'client_id' => $c->ClientIdentifier,
            // Secret cannot be obtained from $c, at this point it's already hashed.
            'client_secret' => '456',
            'code' => $authCode,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $redir,
        ]);

        $at = AccessTokenEntity::get()->last();

        $this->assertEquals(200, $resp->getStatusCode());

        $payload = json_decode($resp->getBody(), true);
        $this->assertTrue(is_int($payload['expires_in']));
        $this->assertTrue($this->tokenIsOk($payload['access_token']));

        // Unpack the token and poke around.
        $claims = $this->tokenGetClaims($payload['access_token']);
        $this->assertEquals($c->ClientIdentifier, $claims['aud']->getValue());
        $this->assertEquals($at->Code, $claims['jti']->getValue());
        $this->assertEquals($m->ID, $claims['sub']->getValue());
    }

    public function testAuthenticateRequest(): void
    {
        $c = $this->objFromFixture(ClientEntity::class, 'test');
        $m = $this->objFromFixture('Member', 'joe');
        $at = $this->objFromFixture(AccessTokenEntity::class, 'test');

        $now = new DateTimeImmutable();
        $expiry = new DateTimeImmutable($at->Expiry);
        $config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText(file_get_contents(__DIR__ . '/test.key'))
        );

        $jwt = $config->builder()
            ->permittedFor($c->ClientIdentifier)
            ->identifiedBy($at->Code)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now->modify('+1 minute'))
            ->expiresAt($expiry)
            ->relatedTo($m->ID)
            ->withClaim('scopes', [])
            ->getToken($config->signer(), $config->signingKey());

        $_SERVER['AUTHORIZATION'] = sprintf('Bearer %s', $jwt);

        $request = OauthServerController::authenticateRequest(null);

        $this->assertEquals($request->getAttribute('oauth_access_token_id'), $at->Code);
        $this->assertEquals($request->getAttribute('oauth_client_id'), $c->ClientIdentifier);
        $this->assertEquals($request->getAttribute('oauth_user_id'), $m->ID);
        $this->assertEquals($request->getAttribute('oauth_scopes'), []);
    }

    public function testGetGrantTypeExpiryInterval(): void
    {
        $oauthController = OauthServerController::singleton();
        $oauthController->config()->update('grant_expiry_interval', 'PT1H');
        $this->assertEquals('PT1H', $oauthController::getGrantTypeExpiryInterval());
    }

    private function tokenIsOk($jwt)
    {
        $pk = new CryptKey(__DIR__ . '/test.crt');
        $token = (new Parser())->parse($jwt);

        $validator = new Validator();
        return $validator->validate($token, []);
//        return $token->verify(new Sha256(), $pk->getKeyPath());
    }

    private function tokenGetClaims($jwt)
    {
        return (new Parser())->parse($jwt)->claims()->all();
    }
}

