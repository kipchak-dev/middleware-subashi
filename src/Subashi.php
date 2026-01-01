<?php

namespace Kipchak\Middleware\Subashi;

use Kipchak\Core\Interfaces;
use Kipchak\Middleware\Subashi\Handlers\Firewall;
use Kipchak\Core\Components\App;

class Subashi implements Interfaces\Middleware
{
    public static function initialise(App $app): void
    {
        $app->add(new Firewall($app->getContainer()));
    }

}