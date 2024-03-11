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
    /**
     * @return RefreshTokenEntity|null
     */
    public function getRefreshToken($tokenId)
    {
        $clients = RefreshTokenEntity::get()->filter([
            'Code' => $tokenId,
        ]);

        /** @var RefreshTokenEntity|null */
        return $clients->first();
    }

    /**
     * {@inheritdoc}
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshToken): void
    {
        /** @var RefreshTokenEntity $refreshTokenEntity */
        $refreshTokenEntity       = $refreshToken;
        $refreshTokenEntity->Code = $refreshTokenEntity->getIdentifier();
        $refreshTokenEntity->write();
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRefreshToken($tokenId): void
    {
        // Some logic to revoke the refresh token in a database
        $token          = $this->getRefreshToken($tokenId);

        if (!$token instanceof RefreshTokenEntity) {
            return;
        }

        $token->Revoked = true;
        $token->write();
    }

    /**
     * {@inheritdoc}
     */
    public function isRefreshTokenRevoked($tokenId): bool
    {
        $token = $this->getRefreshToken($tokenId);

        if (!$token instanceof RefreshTokenEntity) {
            return true;
        }

        return (bool) $token->Revoked;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewRefreshToken(): RefreshTokenEntity
    {
        return RefreshTokenEntity::create();
    }
}
