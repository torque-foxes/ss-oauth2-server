<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateInterval;
use DateTimeImmutable;
use Exception;
use IanSimpson\OAuth2\OauthServerController;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
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
class AccessTokenEntity extends DataObject implements AccessTokenEntityInterface
{
    use AccessTokenTrait;
    use TokenEntityTrait;
    use EntityTrait;

    private static string $table_name = 'OAuth_AccessTokenEntity';

    private static array $db = [
        'Code'    => 'Text',
        'Expiry'  => 'Datetime',
        'Revoked' => 'Boolean',
    ];

    private static array $has_one = [
        'Client' => ClientEntity::class,
    ];

    private static array $many_many = [
        'ScopeEntities' => ScopeEntity::class,
    ];

    public function getIdentifier()
    {
        return $this->Code;
    }

    /**
     * @throws Exception
     */
    public function getExpiryDateTime(): DateTimeImmutable
    {
        $date = new DateTimeImmutable();
        $date->setTimestamp((int) $this->Expiry);

        return $date->add(new DateInterval(OauthServerController::getGrantTypeExpiryInterval()));
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->Client()->MemberID;
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

    public function addScope(ScopeEntityInterface $scope): self
    {
        $this->ScopeEntities()->add($scope);

        return $this;
    }

    public function setScopes($scopes): self
    {
        $this->ScopeEntities()->removeall();
        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }

        return $this;
    }

    public function setClient(ClientEntityInterface $client): self
    {
        $this->ClientID = $client->ID;

        return $this;
    }
}
