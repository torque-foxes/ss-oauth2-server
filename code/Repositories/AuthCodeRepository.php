<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use IanSimpson\OAuth2\Entities\AuthCodeEntity;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use SilverStripe\ORM\DataObject;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function getAuthCode($codeId): null|AuthCodeEntity|DataObject
    {
        $codes = AuthCodeEntity::get()->filter([
            'Code' => $codeId,
        ]);

        return $codes->first();
    }

    /**
     * {@inheritdoc}
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCode): void
    {
        /** @var AuthCodeEntity $authCodeEntity */
        $authCodeEntity       = $authCode;
        $authCodeEntity->Code = $authCodeEntity->getIdentifier();
        $authCodeEntity->write();
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAuthCode($codeId): void
    {
        // Some logic to revoke the auth code in a database
        $code          = $this->getAuthCode($codeId);
        $code->Revoked = true;
        $code->write();
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthCodeRevoked($codeId): bool
    {
        $code = $this->getAuthCode($codeId);

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
