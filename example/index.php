<?php
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(E_ALL);
set_error_handler(function($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
}, E_ALL);

session_start();

use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use SlimAuth\Auth as Auth;

require '../vendor/autoload.php';
require './User.php';

try {
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
    $auth = $app->getContainer()->get('auth');

    $app->get('/', function (Request $request, Response $response) {
        if ($this->get('auth')->getAuthenticated() !== null) {
            $response->getBody()->write(file_get_contents(__DIR__.'/_index2.html'));
        } else {
            $response->getBody()->write(file_get_contents(__DIR__.'/_index.html'));
        }
        return $response;
    });

    $app->get('/admin', function (Request $request, Response $response) {
        $response->getBody()->write(file_get_contents(__DIR__.'/_index2.html'));
        return $response;
    })->add($auth->secure('admin'));

    $app->get('/private', function (Request $request, Response $response) {
        $response->getBody()->write(file_get_contents(__DIR__.'/_index2.html'));
        return $response;
    })->add($auth->secure());

    $app->post('/login', function (Request $request, Response $response) {
        $parsedBody = $request->getParsedBody();
        $user = User::findBy($parsedBody['user_cd']);
        if ($user && $user->authenticate($parsedBody['password'])) {
            $this->get('auth')->permit($user->id);
        }
        return $response->withRedirect('/', 301);
    });

    $app->get('/logout', function (Request $request, Response $response) {
        $this->get('auth')->clear();
        return $response->withRedirect('/', 301);
    });
    $app->run();
} catch (Error $e) {
    var_dump($e);
} catch (ErrorException $e) {
    var_dump($e);
}
