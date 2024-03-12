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
 * @property ?string $Code
 * @property int $Expiry
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


    /**
     * @config
     */
    private static string $table_name = 'OAuth_AccessTokenEntity';


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
     * @var array|string[]
     * @config
     */
    private static array $has_one = [
        'Client' => ClientEntity::class,
    ];


    /**
     * @var array|string[]
     * @config
     */
    private static array $many_many = [
        'ScopeEntities' => ScopeEntity::class,
    ];

    public function getIdentifier(): string
    {
        return (string) $this->Code;
    }

    /**
     * @throws Exception
     */
    public function getExpiryDateTime(): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp((int) $this->Expiry)
            ->add(new DateInterval(OauthServerController::getGrantTypeExpiryInterval()));
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->Client()->MemberID;
    }

    public function getScopes(): array
    {
        return $this->ScopeEntities()->toArray();
    }

    /**
     * @return ClientEntity|null
     */
    public function getClient()
    {
        $clients = ClientEntity::get()->filter([
            'ID' => $this->ClientID,
        ]);

        /** @var ClientEntity|null */
        return $clients->first();
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
        $this->ScopeEntities()->removeall();
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
