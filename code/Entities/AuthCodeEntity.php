<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateTime;
use DateTimeImmutable;
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
 * @property string $Code
 * @property string $Expiry
 * @property bool $Revoked
 * @property int $ClientID
 * @property int $MemberID
 * @method ClientEntity Client()
 * @method Member Member()
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
     * @config
     */
    private static array $db = [
        'Code'    => 'Text',
        'Expiry'  => 'Datetime',
        'Revoked' => 'Boolean',
    ];


    /**
     * @config
     * @var array|string[]
     */
    private static array $has_one = [
        'Client' => ClientEntity::class,
        'Member' => Member::class,
    ];

    /**
     * @config
     * @var array|string[]
     */
    private static array $many_many = [
        'ScopeEntities' => ScopeEntity::class,
    ];

    public function getIdentifier(): string
    {
        return (string) $this->Code;
    }

    public function getExpiryDateTime(): DateTime
    {
        $date = new DateTime();
        $date->setTimestamp((int) $this->Expiry);

        return $date;
    }

    public function getUserIdentifier(): int
    {
        return (int) $this->MemberID;
    }

    public function getScopes(): array
    {
        return $this->ScopeEntities()->toArray();
    }

    public function getClient(): null|ClientEntity|DataObject
    {
        $clients = ClientEntity::get()->filter([
            'ID' => $this->ClientID,
        ]);

        return $clients->first();
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

    public function setUserIdentifier($id): self
    {
        $this->MemberID = $id;

        return $this;
    }

    /**
     * @param ScopeEntity $scope
     */
    public function addScope(ScopeEntityInterface $scope): self
    {
        $this->ScopeEntities()->add($scope);

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

    /**
     * @param ClientEntity $client
     */
    public function setClient(ClientEntityInterface $client): self
    {
        $this->ClientID = $client->ID;

        return $this;
    }
}
