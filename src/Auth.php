<?php
namespace SlimAuth;
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use LogicException;

class Auth
{
    const SESSION_KEY = 'SlimAuth/Auth/targetKey';

    const ATTRIBUTE_NAME = 'authenticated';

    protected $findTarget;

    protected $checkAcl;

    protected $target;

    protected $failure;

    protected $sessionKey;

    protected $attributeName;

    public function __construct(callable $findTarget, $settings = [])
    {
        $this->findTarget = $findTarget;
        $this->checkAcl = $settings['checkAcl'] ?? function($target, $acl) {
            throw new LogicException('Not Implemented. [checkAcl]');
        };
        if (!is_callable($this->checkAcl)) {
            throw new LogicException('Not Implemented. [checkAcl]');
        }
        $this->failure = $settings['failure'] ?? function(Request $request, Response $response) {
            $response->getBody()->write('Forbidden');
            return $response->withStatus(403);
        };
        if (!is_callable($this->failure)) {
            throw new LogicException('Not Implemented. [failure]');
        }
        $this->sessionKey = $settings['sessionKey'] ?? self::SESSION_KEY;
        $this->attributeName = $settings['attributeName'] ?? self::ATTRIBUTE_NAME;
    }

    /**
     * store authenticated user
     * @param mixed
     */
    public function permit($targetKey, $target)
    {
        $_SESSION[$this->sessionKey] = $targetKey;
        $this->target = $target;
    }

    /**
     * release authenticated user
     */
    public function clear()
    {
        $_SESSION[$this->sessionKey] = null;
        $this->target = null;
    }

    /**
     * intercept
     */
    public function intercept(Request $request, Response $response, callable $next, $acl = null)
    {
        list($result, $target) = $this->authenticate($request, $acl);
        if($result !== true) {
            return $this->invokeFailure($request, $response);
        }
        $this->target = $target;
        $request = $request->withAttribute($this->attributeName, $target);
        return $next($request, $response);
    }

    public function getAuthenticated(Request $request = null)
    {
        if ($this->target === null) {
            $this->target = call_user_func($this->findTarget, $this->getTargetKey(), $request);
        }
        return $this->target;
    }

    protected function authenticate(Request $request, $acl = null)
    {
        $target = $this->getAuthenticated($request);
        if (!$target) {
            return [false, null];
        } else if ($acl === null) {
            return [true, $target];
        }
        $acl = is_array($acl) ? $acl : [$acl];
        return [call_user_func($this->checkAcl, $target, $acl), $target];
    }

    protected function getTargetKey()
    {
        return $_SESSION[$this->sessionKey] ?? null;
    }

    protected function invokeFailure(Request $request, Response $response)
    {
        return call_user_func($this->failure, $request, $response);
    }

    static public function secure($acl = null)
    {
        return function(Request $request, Response $response, callable $next) use ($acl) {
            return $this->get('auth')->intercept($request, $response, $next, $acl);
        };
    }

}
