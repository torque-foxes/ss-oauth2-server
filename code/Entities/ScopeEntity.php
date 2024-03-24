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

    /**
     * @config
     */
    private static string $table_name = 'OAuth_ScopeEntity';

    /**
     * @config
     */
    private static string $singular_name = 'OAuth Scope';

    /**
     * @config
     */
    private static string $plural_name   = 'OAuth Scopes';

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $db = [
        'ScopeIdentifier'  => 'Varchar(32)',
        'ScopeDescription' => 'Text',
    ];

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $has_one = [
        'SiteConfig' => SiteConfig::class,
    ];

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $summary_fields = [
        'ScopeIdentifier',
    ];

    /**
     * @config
     *
     * @var array<string, array<string, array<int, string>|string>>
     */
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
