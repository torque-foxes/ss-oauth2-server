<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use IanSimpson\OAuth2\Entities\ClientEntity;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getClientEntity($clientIdentifier, $grantType = null, $clientSecret = null, $mustValidateSecret = true)
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

        if ($mustValidateSecret === true
            && !$client->isSecretValid($clientSecret)
        ) {
            return null;
        }

        return $client;
    }

    /**
     * @inheritDoc
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType)
    {
        $client = $this->getClientEntity($clientIdentifier);
        
        if ($client->ClientConfidential === true
            && !$client->isSecretValid($clientSecret)
        ) {
            return false;
        }

        return true;
    }
}
