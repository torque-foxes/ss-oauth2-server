<?php

namespace IanSimpson\Tests;

use DateTimeImmutable;
use GuzzleHttp\Psr7\Query;
use IanSimpson\OAuth2\Entities\AccessTokenEntity;
use IanSimpson\OAuth2\Entities\AuthCodeEntity;
use IanSimpson\OAuth2\Entities\ClientEntity;
use IanSimpson\OAuth2\OauthServerController;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use Monolog\Logger;
use PHPUnit\Framework\MockObject\MockObject;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\Security\Member;

/**
 * @internal
 */
class OauthServerControllerTest extends FunctionalTest
{
    use CryptTrait;

    protected static $fixture_file = 'OauthServerControllerTest.yml';

    protected $autoFollowRedirection = false;

    /**
     * @var Logger|MockObject
     */
    private $logger;

    private Configuration $configuration;

    protected function setUp(): void
    {
        parent::setUp();

        Config::nest();

        $_SERVER['SERVER_PORT'] = 80;

        $publicKey  = __DIR__ . '/public.key';
        $privateKey = __DIR__ . '/private.key';
        $encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen';

        Environment::putEnv('OAUTH_PUBLIC_KEY_PATH=' . $publicKey);
        Environment::putEnv('OAUTH_PRIVATE_KEY_PATH=' . $privateKey);
        Environment::putEnv('OAUTH_ENCRYPTION_KEY=' . $encryptionKey);

        $this->setEncryptionKey($encryptionKey);

        $this->configuration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText(file_get_contents(__DIR__ . '/private.key'))
        );

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
        $this->markTestSkipped('Currently returns a 401.');

        $state = 789;
        $c     = $this->objFromFixture(ClientEntity::class, 'test');
        $m     = $this->objFromFixture(Member::class, 'joe');
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

        $this->assertSame(302, $resp->getStatusCode());
        $url   = parse_url($resp->getHeader('Location'));
        $query = Query::parse($url['query']);
        $this->assertSame($url['host'], 'client');
        $this->assertSame($url['path'], '/callback');
        $this->assertSame($query['state'], $state);

        // Have a look inside payload too.
        $payload        = json_decode($this->decrypt($query['code']), true);
        $authCodeEntity = AuthCodeEntity::get()->filter('Code', $payload['auth_code_id'])->first();
        $this->assertSame($payload['client_id'], $c->ClientIdentifier);
        $this->assertSame($payload['user_id'], $m->ID);
        $this->assertNotNull($authCodeEntity);
    }

    public function testAccessToken(): void
    {
        $redir = 'http://client/callback';
        $c     = $this->objFromFixture(ClientEntity::class, 'test');
        $m     = $this->objFromFixture(Member::class, 'joe');
        $ac    = $this->objFromFixture(AuthCodeEntity::class, 'test');

        // Make fake code.
        $payload = [
            'client_id'             => $c->ClientIdentifier,
            'redirect_uri'          => $redir,
            'auth_code_id'          => $ac->Code,
            'scopes'                => [],
            'user_id'               => $m->ID,
            'expire_time'           => strtotime('2099-06-06 12:00:00'),
            'code_challenge'        => null,
            'code_challenge_method' => null,
        ];

        $authCode = $this->encrypt(json_encode($payload));

        $resp = $this->post('http://localhost/oauth/accessToken', [
            'client_id' => $c->ClientIdentifier,
            // Secret cannot be obtained from $c, at this point it's already hashed.
            'client_secret' => '456',
            'code'          => $authCode,
            'grant_type'    => 'authorization_code',
            'redirect_uri'  => $redir,
        ]);

        $at = AccessTokenEntity::get()->last();

        $this->assertSame(200, $resp->getStatusCode());

        $payload = json_decode($resp->getBody(), true);

        $this->assertIsInt($payload['expires_in']);
        $this->assertIsString($payload['access_token']);

        $constraints = [
            new IdentifiedBy($at->Code),
            new PermittedFor($c->ClientIdentifier),
            new RelatedTo(''),
        ];

        $token = $this->configuration->parser()->parse($payload['access_token']);

        $this->assertTrue($this->configuration->validator()->validate($token, ...$constraints));
    }

    public function testAuthenticateRequest(): void
    {
        $this->markTestSkipped('Method call will currently throw an error.');

        $c  = $this->objFromFixture(ClientEntity::class, 'test');
        $m  = $this->objFromFixture('Member', 'joe');
        $at = $this->objFromFixture(AccessTokenEntity::class, 'test');

        $now    = new DateTimeImmutable();
        $expiry = new DateTimeImmutable($at->Expiry);

        $jwt = $this->configuration->builder()
            ->permittedFor($c->ClientIdentifier)
            ->identifiedBy($at->Code)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now->modify('+1 minute'))
            ->expiresAt($expiry)
            ->relatedTo($m->ID)
            ->withClaim('scopes', [])
            ->getToken($this->configuration->signer(), $this->configuration->signingKey());

        $_SERVER['AUTHORIZATION'] = sprintf('Bearer %s', $jwt->toString());

        $request = OauthServerController::authenticateRequest(null);

        $this->assertSame($request->getAttribute('oauth_access_token_id'), $at->Code);
        $this->assertSame($request->getAttribute('oauth_client_id'), $c->ClientIdentifier);
        $this->assertSame($request->getAttribute('oauth_user_id'), $m->ID);
        $this->assertSame($request->getAttribute('oauth_scopes'), []);
    }

    public function testGetGrantTypeExpiryInterval(): void
    {
        $oauthController = OauthServerController::singleton();
        $oauthController->config()->update('grant_expiry_interval', 'PT1H');
        $this->assertSame('PT1H', $oauthController::getGrantTypeExpiryInterval());
    }

    private function tokenIsOk(string $jwt): bool
    {
        // $pk    = new CryptKey(__DIR__ . '/test.crt');
        // $token = (new Parser(new Decoder))->parse($jwt);

        // $validator = new Validator();

        $token = $this->configuration->parser()->parse($jwt);

        return $this->configuration->validator()->validate($token);

        // return $validator->validate($token);
            //    return $token->verify(new Sha256(), $pk->getKeyPath());
    }

    private function tokenGetClaims(string $jwt): array
    {
        $token = $this->configuration->parser()->parse($jwt);

        return $token->claims()->all();
    }
}
