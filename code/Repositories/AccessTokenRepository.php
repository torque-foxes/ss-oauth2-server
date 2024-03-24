<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use IanSimpson\OAuth2\Entities\AccessTokenEntity;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function getAccessToken(string $tokenId): ?AccessTokenEntity
    {
        $clients = AccessTokenEntity::get()->filter([
            'Code' => $tokenId,
        ]);

        // @var AccessTokenEntity|null
        return $clients->first();
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessToken): void
    {
        if (!$accessToken instanceof AccessTokenEntity) {
            return;
        }

        $accessTokenEntity = $accessToken;
        $accessTokenEntity->Code = $accessTokenEntity->getIdentifier();
        $accessTokenEntity->write();
    }

    public function revokeAccessToken($tokenId): void
    {
        // Some logic here to revoke the access token
        $token = $this->getAccessToken($tokenId);

        if (!$token instanceof AccessTokenEntity) {
            return;
        }

        $token->Revoked = true;
        $token->write();
    }

    public function isAccessTokenRevoked($tokenId): bool
    {
        $token = $this->getAccessToken($tokenId);

        if (!$token instanceof AccessTokenEntity) {
            return true;
        }

        return (bool) $token->Revoked;
    }

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null): AccessTokenEntityInterface
    {
        $accessToken = AccessTokenEntity::create();
        $accessToken->setClient($clientEntity);

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        $accessToken->setUserIdentifier($userIdentifier);

        return $accessToken;
    }
}
