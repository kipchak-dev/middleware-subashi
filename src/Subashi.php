<?php

namespace Kipchak\Middleware\Auth;

use Kipchak\Core\Interfaces;
use Kipchak\Driver\Config\Config;
use Kipchak\Middleware\Auth\Handlers\AuthJwks;
use Kipchak\Middleware\Auth\Handlers\AuthKey;
use Kipchak\Middleware\Subashi\Handlers\Firewall;
use Slim\App;

class Subashi implements Interfaces\Middleware
{
    public static function initialise(App $app): void
    {
        $app->add(new Firewall($app->getContainer()));
    }

}