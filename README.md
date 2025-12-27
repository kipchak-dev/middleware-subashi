# Subashi - A WAF Middleware for Kipchak

This Middleware package adds WAF capabilities to your Kipchak API.

It's name is inspired by the Arabic word "Subashi" which means "shield" or "protection", reflecting the purpose of the middleware to protect your API from malicious attacks.

It's actually taken from the Ottoman Turkish *subaşı*, which was title given to the police chief of a city / town in the Ottoman Empire.

#### Composer Package

`kipchak/middleware-subashi`

## How to use it?

Install it via composer: `composer require kipchak/middleware-subashi`.

Then just ensure you have appropriate settings configured in `kipchak.subashi.php` config file in the root of your project.

For a sample, please see: https://1x.ax/mamluk/kipchak/starter/~files/master/config/kipchak.subashi.php.

## What is a Kipchak Middleware?

Kipchak Middleware is a standard PHP PSR-15 middleware.

Middleware is a component that sits between the request and response of a web application, allowing for interception
and modification of the request and response data. In the context of Kipchak, middleware can be used to handle errors,
authentication, and other cross-cutting concerns that are common across one or more API endpoints.
