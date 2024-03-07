<?php

namespace IanSimpson\OAuth2\Admin;

use IanSimpson\OAuth2\Entities\ScopeEntity;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldAddNewButton;
use SilverStripe\Forms\GridField\GridFieldConfig;
use SilverStripe\Forms\GridField\GridFieldDataColumns;
use SilverStripe\Forms\GridField\GridFieldDeleteAction;
use SilverStripe\Forms\GridField\GridFieldDetailForm;
use SilverStripe\Forms\GridField\GridFieldEditButton;
use SilverStripe\Forms\GridField\GridFieldToolbarHeader;
use SilverStripe\ORM\DataExtension;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * @method SiteConfig getOwner()
 */
class ScopeAdmin extends DataExtension
{
    private static array $has_many = [
        'Scopes' => ScopeEntity::class,
    ];

    public function updateCMSFields(FieldList $fields): void
    {
        $gridFieldConfig = GridFieldConfig::create();
        $button          = GridFieldAddNewButton::create('toolbar-header-right');
        $button->setButtonName('Add New OAuth Scope');
        $gridFieldConfig->addComponents(
            GridFieldToolbarHeader::create(),
            $button,
            GridFieldDataColumns::create(),
            GridFieldEditButton::create(),
            GridFieldDeleteAction::create(),
            GridFieldDetailForm::create()
        );

        $fields->addFieldToTab(
            'Root.OAuthConfiguration',
            GridField::create(
                'Scopes',
                'Scopes',
                $this->getOwner()->Scopes(),
                $gridFieldConfig
            )
        );
    }
}
