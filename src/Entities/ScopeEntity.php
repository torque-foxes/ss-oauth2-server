<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use SilverStripe\ORM\DataObject;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * @property string $ScopeIdentifier
 * @property string $ScopeDescription
 * @property int $SiteConfigID
 * @method SiteConfig SiteConfig()
 */
class ScopeEntity extends DataObject implements ScopeEntityInterface
{
    use EntityTrait;

    private static string $table_name = 'OAuth_ScopeEntity';

    private static string $singular_name = 'OAuth Scope';
    private static string $plural_name   = 'OAuth Scopes';

    private static array $db = [
        'ScopeIdentifier'  => 'Varchar(32)',
        'ScopeDescription' => 'Text',
    ];

    private static array $has_one = [
        'SiteConfig' => SiteConfig::class,
    ];

    private static array $summary_fields = [
        'ScopeIdentifier',
    ];

    private static array $indexes = [
        'ScopeIdentifier' => [
            'type'    => 'index',
            'columns' => ['ScopeIdentifier'],
        ],
        'ScopeIdentifierUnique' => [
            'type'    => 'unique',
            'columns' => ['ScopeIdentifier'],
        ],
    ];

    public function jsonSerialize(): mixed
    {
        return $this->ScopeIdentifier;
    }
}
