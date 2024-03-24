<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use IanSimpson\OAuth2\Entities\AuthCodeEntity;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function getAuthCode(string $codeId): ?AuthCodeEntity
    {
        $codes = AuthCodeEntity::get()->filter([
            'Code' => $codeId,
        ]);

        // @var AuthCodeEntity|null
        return $codes->first();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCode): void
    {
        if (!$authCode instanceof AuthCodeEntity) {
            return;
        }

        $authCodeEntity = $authCode;
        $authCodeEntity->Code = $authCodeEntity->getIdentifier();
        $authCodeEntity->write();
    }

    public function revokeAuthCode($codeId): void
    {
        // Some logic to revoke the auth code in a database
        $code = $this->getAuthCode($codeId);

        if (!$code instanceof AuthCodeEntity) {
            return;
        }

        $code->Revoked = true;
        $code->write();
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthCodeRevoked($codeId): bool
    {
        $code = $this->getAuthCode($codeId);

        if (!$code instanceof AuthCodeEntity) {
            return true;
        }

        return (bool) $code->Revoked;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewAuthCode(): AuthCodeEntity
    {
        return AuthCodeEntity::create();
    }
}
