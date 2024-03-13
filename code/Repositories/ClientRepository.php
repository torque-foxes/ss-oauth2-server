<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use IanSimpson\OAuth2\Entities\ClientEntity;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getClientEntity($clientIdentifier): ?ClientEntity
    {
        $clients = ClientEntity::get()->filter([
            'ClientIdentifier' => $clientIdentifier,
        ]);

        // Check if client is registered
        if (!$clients->exists()) {
            return null;
        }

        /** @var ClientEntity $client */
        $client = $clients->first();
        $client->setConfidential();

        return $client;
    }

    /**
     * {@inheritDoc}
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType = null): bool
    {
        $client = $this->getClientEntity($clientIdentifier);

        if (
            $client instanceof ClientEntity && $client->ClientConfidential
                                            && $client->isSecretValid((string) $clientSecret)
        ) {
            return true;
        }

        return false;
    }
}
