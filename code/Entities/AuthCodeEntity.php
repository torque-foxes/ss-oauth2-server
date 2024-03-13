<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateTimeImmutable;
use Exception;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\Security\Member;

/**
 * @property ?string $Code
 * @property int     $Expiry
 * @property bool    $Revoked
 * @property int     $ClientID
 * @property int     $MemberID
 *
 * @method ClientEntity               Client()
 * @method Member                     Member()
 * @method ManyManyList|ScopeEntity[] ScopeEntities()
 */
class AuthCodeEntity extends DataObject implements AuthCodeEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;
    use AuthCodeTrait;

    /**
     * @config
     */
    private static string $table_name = 'OAuth_AuthCodeEntity';

    /**
     * @var array|string[]
     *
     * @config
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
        'Client' => ClientEntity::class,
        'Member' => Member::class,
    ];

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $many_many = [
        'ScopeEntities' => ScopeEntity::class,
    ];

    public function getIdentifier(): string
    {
        return (string) $this->Code;
    }

    public function getExpiryDateTime(): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp($this->Expiry);
    }

    public function getUserIdentifier(): int
    {
        return $this->MemberID;
    }

    public function getScopes(): array
    {
        return $this->ScopeEntities()->toArray();
    }

    /**
     * @return ClientEntity
     */
    public function getClient(): ClientEntityInterface
    {
        return $this->Client();
    }

    public function setIdentifier(mixed $code): self
    {
        $this->Code = (string) $code;

        return $this;
    }

    public function setExpiryDateTime(DateTimeImmutable $expiry): self
    {
        $this->Expiry = $expiry->getTimestamp();

        return $this;
    }

    public function setUserIdentifier(mixed $id): self
    {
        $this->MemberID = (int) $id;

        return $this;
    }

    public function addScope(ScopeEntityInterface $scope): self
    {
        if ($scope instanceof ScopeEntity) {
            $this->ScopeEntities()->add($scope);
        }

        return $this;
    }

    /**
     * @param ScopeEntity[] $scopes
     */
    public function setScopes($scopes): self
    {
        $this->ScopeEntities()->removeAll();

        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }

        return $this;
    }

    public function setClient(ClientEntityInterface $client): self
    {
        if ($client instanceof ClientEntity) {
            $this->ClientID = $client->ID;
        }

        return $this;
    }
}
