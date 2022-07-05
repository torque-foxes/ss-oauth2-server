<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateTime;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\ORM\SS_List;
use SilverStripe\Security\Member;

/**
 * @property string Code
 * @property string Expiry
 * @property bool Revoked
 * @property int ClientID
 * @property int MemberID
 * @property SS_List ScopeEntities
 * @method ClientEntity Client()
 * @method Member Member()
 * @method ManyManyList ScopeEntities()
 */
class AccessTokenEntity extends DataObject implements AccessTokenEntityInterface
{
    use AccessTokenTrait, TokenEntityTrait, EntityTrait;

    private static $table_name = 'OAuth_AccessTokenEntity';

    private static $db = [
        'Code' => 'Text',
        'Expiry' => 'Datetime',
        'Revoked' => 'Boolean'
    ];

    private static $has_one = [
        'Client' => ClientEntity::class,
    ];

    private static $many_many = [
        'ScopeEntities' => ScopeEntity::class
    ];

    public function getIdentifier()
    {
        return $this->Code;
    }

    public function getExpiryDateTime()
    {
        $date = new DateTime();
        $date->setTimestamp((int) $this->Expiry);

        return $date;
    }

    public function getUserIdentifier()
    {
        return $this->Client()->MemberID;
    }

    public function getScopes()
    {
        return $this->ScopeEntities()->toArray();
    }

    public function getClient()
    {
        $clients = ClientEntity::get()->filter(array(
            'ID' => $this->ClientID
        ));
        /** @var ClientEntity $client */
        $client = $clients->first();
        return $client;
    }


    public function setIdentifier($code)
    {
        $this->Code = $code;
    }

    public function setExpiryDateTime(DateTime $expiry)
    {
        $this->Expiry = $expiry->getTimestamp();
    }

    public function setUserIdentifier($id)
    {
        $this->MemberID = $id;
    }

    public function addScope(ScopeEntityInterface $scope)
    {
        $this->ScopeEntities()->add($scope);
    }

    public function setScopes($scopes)
    {
        $this->ScopeEntities()->removeall();
        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }
    }

    public function setClient(ClientEntityInterface $client)
    {
        /** @var ClientEntity $clientEntity */
        $clientEntity = $client;
        $this->ClientID = $clientEntity->ID;
    }
}
