<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use SilverStripe\ORM\DataObject;

/**
 * @property ?string $Code
 * @property int $Expiry
 * @property bool $Revoked
 * @property int $AccessTokenID
 * @method AccessTokenEntity AccessToken()
 */
class RefreshTokenEntity extends DataObject implements RefreshTokenEntityInterface
{
    use RefreshTokenTrait;
    use EntityTrait;

    /**
     * @config
     */
    private static string $table_name = 'OAuth_RefreshTokenEntity';

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $db = [
        'Code'    => 'Text',
        'Expiry'  => 'Datetime',
        'Revoked' => 'Boolean',
    ];

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $has_one = [
        'AccessToken' => AccessTokenEntity::class,
    ];

    public function getIdentifier(): string
    {
        return (string) $this->Code;
    }

    public function getExpiryDateTime(): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp((int) $this->Expiry);
    }

    /**
     * @return AccessTokenEntity
     */
    public function getAccessToken(): AccessTokenEntityInterface
    {
        return $this->AccessToken();
    }

    public function setIdentifier($code): self
    {
        $this->Code = $code;

        return $this;
    }

    public function setExpiryDateTime(DateTimeImmutable $expiry): self
    {
        $this->Expiry = $expiry->getTimestamp();

        return $this;
    }

    public function setAccessToken(AccessTokenEntityInterface $accessToken): self
    {
        if ($accessToken instanceof AccessTokenEntity) {
            $this->AccessTokenID = $accessToken->ID;
        }

        return $this;
    }
}
