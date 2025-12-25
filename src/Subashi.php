<?php

namespace Kipchak\Middleware\Subashi;

use Kipchak\Core\Interfaces;
use Kipchak\Middleware\Subashi\Handlers\Firewall;
use Slim\App;

class Subashi implements Interfaces\Middleware
{
    public static function initialise(App $app): void
    {
        $app->add(new Firewall($app->getContainer()));
    }

}