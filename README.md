# Auth Middleware for Slim

Unofficial auth middleware for Slim Framework.

apply authentication and authorization settings to each route.

## Usage

#### Registration of middleware

```php
<?php
session_start();

$app = new \Slim\App([
    'auth' => function($c) {
        return new SlimAuth\Auth(function($id) {
            return User::findOne($id);  // null => 403 response.
        });
    }
]);
```

#### Route settings

use **secure** method.

```php
<?php
$auth = $app->getContainer()->get('auth');

$app->get('/private', function ($request, $response) {
    $response->getBody()->write('OK');
    return $response;
})->add($auth->secure());
```

#### Session authentication

use **permit** method.

```php
<?php
$app->post('/login', function ($request, $response) {
    $parsedBody = $request->getParsedBody();
    $user = User::findBy($parsedBody['user_cd']);
    if ($user && $user->authenticate($parsedBody['password'])) {
        $this->get('auth')->permit($user->id);
    }
    return $response->withRedirect('/', 301);
});
```

#### Dispose session authentication

use **clear** method.

```php
<?php
$app->get('/logout', function ($request, $response) {
    $this->get('auth')->clear();
    return $response->withRedirect('/', 301);
});
```

## Advanced Usage

#### ACL authorization

use **checkAcl** option.

```php
<?php
$app = new \Slim\App([
    'auth' => function($c) {
        return new SlimAuth\Auth(function($id) {
            return User::findOne($id);
        }, [
            'checkAcl' => function($currentUser, $acl) {
                return $currentUser->allowAccess($acl);
            }
        ]);
    }
]);
```

use **secure** method with acl list.

```php
<?php
$auth = $app->getContainer()->get('auth');

$app->get('/admin', function ($request, $response) {
    $response->getBody()->write('OK');
    return $response;
})->add($auth->secure(['admin', 'superuser']));
```

#### Extra failure

use **failure** option.

```php
<?php
$app = new \Slim\App([
    'auth' => function($c) {
        return new SlimAuth\Auth(function($id) {
            return User::findOne($id);
        }, [
            'failure' => function($request, $response) {
                return $response->withRedirect('/', 301);
            }
        ]);
    }
]);
```

## Example

Start the sample with the following command.

```bash
$ php -S localhost:8080 -t example
```
