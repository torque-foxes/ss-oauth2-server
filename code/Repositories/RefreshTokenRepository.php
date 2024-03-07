<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use IanSimpson\OAuth2\Entities\RefreshTokenEntity;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use SilverStripe\ORM\DataObject;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getRefreshToken($tokenId): null|DataObject|RefreshTokenEntity
    {
        $clients = RefreshTokenEntity::get()->filter([
            'Code' => $tokenId,
        ]);

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
        $token->Revoked = true;
        $token->write();
    }

    /**
     * {@inheritdoc}
     */
    public function isRefreshTokenRevoked($tokenId): bool
    {
        $token = $this->getRefreshToken($tokenId);

        return (bool) $token->Revoked;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewRefreshToken(): RefreshTokenEntity
    {
        return new RefreshTokenEntity();
    }
}
