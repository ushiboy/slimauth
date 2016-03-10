<?php
namespace SlimAuth\Tests;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Slim\Http\Body;
use Slim\Http\Collection;
use Slim\Http\Environment;
use Slim\Http\Headers;
use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Uri;
use SlimAuth\Auth;
use LogicException;

class User
{
    public $id;
    public $name;
    public function __construct($id, $name) {
        $this->id = $id;
        $this->name = $name;
    }
}

class AuthTest extends \PHPUnit_Framework_TestCase
{
    protected $user;
    protected $request;
    protected $response;
    protected $findTarget;

    /**
     * Run before each test
     */
    public function setUp()
    {
        $this->user = new User(10001, 'test');
        $this->findTarget = function($id, $request) {
            return $id === $this->user->id ? $this->user : null;
        };
        $uri = Uri::createFromString('https://example.com');
        $headers = new Headers();
        $cookies = [];
        $env = Environment::mock();
        $serverParams = $env->all();
        $body = new Body(fopen('php://temp', 'r+'));
        $this->request = new Request('GET', $uri, $headers, $cookies, $serverParams, $body);
        $this->response = new Response;
    }

    public function tearDown()
    {
        $_SESSION[Auth::SESSION_KEY] = null;
    }

    /**
     * @expectedException LogicException
     */
    public function testConstructor__when_matchAcl_setting_is_not_callable()
    {
        new Auth($this->findTarget, [
            'checkAcl' => true
        ]);
    }

    /**
     * @expectedException LogicException
     */
    public function testConstructor__when_failure_setting_is_not_callable()
    {
        new Auth($this->findTarget, [
            'failure' => true
        ]);
    }

    public function testPermit()
    {
        $user = $this->user;
        $auth = new Auth($this->findTarget);
        $auth->permit($user->id);
        $this->assertEquals($user->id, $_SESSION[Auth::SESSION_KEY]);
    }

    public function testPermit__when_use_extra_sessionKey()
    {
        $user = $this->user;
        $myKey = 'MyKEY';
        $auth = new Auth($this->findTarget, [
            'sessionKey' => $myKey
        ]);
        $auth->permit($user->id);
        $this->assertEquals($user->id, $_SESSION[$myKey]);
    }

    public function testClear()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $auth = new Auth($this->findTarget);
        $auth->clear();
        $this->assertNull($_SESSION[Auth::SESSION_KEY]);
    }

    public function testIntercept()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $auth = new Auth($this->findTarget);
        $next = function($request, $response) use (&$resultUser) {
            $response->getBody()->write('OK');
            return $response->withStatus(200);
        };
        $response = $auth->intercept($this->request, $this->response, $next);
        $this->assertEquals('OK', $response->getBody());
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testIntercept__when_use_acl()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $resultAcl = [];
        $auth = new Auth($this->findTarget, [
            'checkAcl' => function($target, $acl) use(&$resultAcl) {
                $resultAcl = $acl;
                return true;
            }
        ]);
        $next = function($request, $response) use (&$resultUser) {
            $response->getBody()->write('OK');
            return $response->withStatus(200);
        };
        $response = $auth->intercept($this->request, $this->response, $next, 'admin');
        $this->assertEquals('OK', $response->getBody());
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(['admin'], $resultAcl);
    }

    public function testIntercept__when_failure()
    {
        $auth = new Auth($this->findTarget);
        $next = function($request, $response) {
            $response->getBody()->write('OK');
            return $response->withStatus(200);
        };
        $response = $auth->intercept($this->request, $this->response, $next);
        $this->assertEquals('Forbidden', $response->getBody());
        $this->assertEquals(403, $response->getStatusCode());
    }

    public function testIntercept__when_acl_failure()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $resultAcl = [];
        $auth = new Auth($this->findTarget, [
            'checkAcl' => function($target, $acl) use(&$resultAcl) {
                $resultAcl = $acl;
                return false;
            }
        ]);
        $next = function($request, $response) {
            $response->getBody()->write('OK');
            return $response->withStatus(200);
        };
        $response = $auth->intercept($this->request, $this->response, $next, ['group1', 'group2']);
        $this->assertEquals('Forbidden', $response->getBody());
        $this->assertEquals(403, $response->getStatusCode());
        $this->assertEquals(['group1', 'group2'], $resultAcl);
    }

    public function testIntercept__when_use_extra_failure()
    {
        $auth = new Auth($this->findTarget, [
            'failure' => function($request, $response) {
                return $response->withRedirect('/', 301);
            }
        ]);
        $next = function($request, $response) {
            $response->getBody()->write('OK');
            return $response->withStatus(200);
        };
        $response = $auth->intercept($this->request, $this->response, $next);
        $this->assertEquals(301, $response->getStatusCode());
    }

    public function testSecure()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $auth = new Auth($this->findTarget);
        $next = function($request, $response) use (&$resultUser) {
            $response->getBody()->write('OK');
            return $response->withStatus(200);
        };
        $fn = $auth->secure();
        $response = $fn($this->request, $this->response, $next);
        $this->assertEquals('OK', $response->getBody());
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testSecure__when_use_acl()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $resultAcl = [];
        $auth = new Auth($this->findTarget, [
            'checkAcl' => function($target, $acl) use(&$resultAcl) {
                $resultAcl = $acl;
                return true;
            }
        ]);
        $next = function($request, $response) use (&$resultUser) {
            $response->getBody()->write('OK');
            return $response->withStatus(200);
        };
        $fn = $auth->secure('admin');
        $response = $fn($this->request, $this->response, $next);
        $this->assertEquals('OK', $response->getBody());
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(['admin'], $resultAcl);
    }

    public function testGetAuthenticated()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $auth = new Auth($this->findTarget);
        $this->assertEquals($this->user, $auth->getAuthenticated());
    }

}
