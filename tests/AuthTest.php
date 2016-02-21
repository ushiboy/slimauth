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
    public function test_initialize__settings_not_callable_matchAcl()
    {
        new Auth($this->findTarget, [
            'checkAcl' => true
        ]);
    }

    /**
     * @expectedException LogicException
     */
    public function test_initialize__settings_not_callable_failure()
    {
        new Auth($this->findTarget, [
            'failure' => true
        ]);
    }

    public function test_permit()
    {
        $user = $this->user;
        $auth = new Auth($this->findTarget);
        $auth->permit($user->id, $user);
        $this->assertEquals($user->id, $_SESSION[Auth::SESSION_KEY]);
    }

    public function test_clear()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $auth = new Auth($this->findTarget);
        $auth->clear();
        $this->assertNull($_SESSION[Auth::SESSION_KEY]);
    }

    public function test_intercept()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $auth = new Auth($this->findTarget);
        $resultUser = [];
        $next = function($request, $response) use (&$resultUser) {
            $resultUser = $request->getAttribute(Auth::ATTRIBUTE_NAME);
            $response->getBody()->write('OK');
            return $response->withStatus(200);
        };
        $response = $auth->intercept($this->request, $this->response, $next);
        $this->assertEquals('OK', $response->getBody());
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals($this->user, $resultUser);
    }

    public function test_intercept__with_acl()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $resultUser = [];
        $resultAcl = [];
        $auth = new Auth($this->findTarget, [
            'checkAcl' => function($target, $acl) use(&$resultAcl) {
                $resultAcl = $acl;
                return true;
            }
        ]);
        $next = function($request, $response) use (&$resultUser) {
            $resultUser = $request->getAttribute(Auth::ATTRIBUTE_NAME);
            $response->getBody()->write('OK');
            return $response->withStatus(200);
        };
        $response = $auth->intercept($this->request, $this->response, $next, 'admin');
        $this->assertEquals('OK', $response->getBody());
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals($this->user, $resultUser);
        $this->assertEquals(['admin'], $resultAcl);
    }

    public function test_intercept__with_failure()
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

    public function test_intercept__with_acl_check_fail()
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

    public function test_getAuthenticated()
    {
        $_SESSION[Auth::SESSION_KEY] = $this->user->id;
        $auth = new Auth($this->findTarget);
        $this->assertEquals($this->user, $auth->getAuthenticated());
    }
}
