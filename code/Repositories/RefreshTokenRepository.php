<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use IanSimpson\OAuth2\Entities\RefreshTokenEntity;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getRefreshToken(string $tokenId): ?RefreshTokenEntity
    {
        $clients = RefreshTokenEntity::get()->filter([
            'Code' => $tokenId,
        ]);

        // @var RefreshTokenEntity|null
        return $clients->first();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshToken): void
    {
        if (!$refreshToken instanceof RefreshTokenEntity) {
            return;
        }

        $refreshTokenEntity = $refreshToken;
        $refreshTokenEntity->Code = $refreshTokenEntity->getIdentifier();
        $refreshTokenEntity->write();
    }

    public function revokeRefreshToken($tokenId): void
    {
        // Some logic to revoke the refresh token in a database
        $token = $this->getRefreshToken((string) $tokenId);

        if (!$token instanceof RefreshTokenEntity) {
            return;
        }

        $token->Revoked = true;
        $token->write();
    }

    public function isRefreshTokenRevoked($tokenId): bool
    {
        $token = $this->getRefreshToken($tokenId);

        if (!$token instanceof RefreshTokenEntity) {
            return true;
        }

        return (bool) $token->Revoked;
    }

    /**
     * @return RefreshTokenEntity
     */
    public function getNewRefreshToken(): RefreshTokenEntityInterface
    {
        return RefreshTokenEntity::create();
    }
}
