<?php
namespace SlimAuth;
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use LogicException;

/**
 * Auth middleware
 */
class Auth
{
    const SESSION_KEY = 'SlimAuth/Auth/targetKey';

    /**
     * handler for findding authenticated target
     *
     * @var callable
     */
    protected $findTarget;

    /**
     * handler for checking acl
     *
     * @var callable
     */
    protected $checkAcl;

    /**
     * authenticated target
     *
     * @var mixed
     */
    protected $target;

    /**
     * handler for auth fail
     *
     * @var callable
     */
    protected $failure;

    /**
     * name of authenticated target session key
     *
     * @var string
     */
    protected $sessionKey;

    /**
     * constructor
     *
     * @param callable $findTarget
     *
     * $settings['checkAcl']        callable check acl handler
     * $settings['failure']         callable extra failure handler
     * $settings['sessionKey']      string extra session key
     * @param array $settings (optional)
     */
    public function __construct(callable $findTarget, $settings = [])
    {
        $this->findTarget = $findTarget;
        if (isset($settings['checkAcl'])) {
            $this->checkAcl = $settings['checkAcl'];
        } else {
            $this->checkAcl = function($target, $acl) {
                throw new LogicException('Not Implemented. [checkAcl]');
            };
        }
        if (!is_callable($this->checkAcl)) {
            throw new LogicException('Not Implemented. [checkAcl]');
        }
        if (isset($settings['failure'])) {
            $this->failure = $settings['failure'];
        } else {
            $this->failure = function(Request $request, Response $response) {
                $response->getBody()->write('Forbidden');
                return $response->withStatus(403);
            };
        }
        if (!is_callable($this->failure)) {
            throw new LogicException('Not Implemented. [failure]');
        }
        if (isset($settings['sessionKey'])) {
            $this->sessionKey = $settings['sessionKey'];
        } else {
            $this->sessionKey = self::SESSION_KEY;
        }
    }

    /**
     * store authenticated target
     *
     * @param mixed $targetKey
     */
    public function permit($targetKey)
    {
        $_SESSION[$this->sessionKey] = $targetKey;
    }

    /**
     * release authenticated target
     */
    public function clear()
    {
        $_SESSION[$this->sessionKey] = null;
        $this->target = null;
    }

    /**
     * intercept route
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param callable $next
     * @param null|string|string[] $acl (optional)
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function intercept(Request $request, Response $response, callable $next, $acl = null)
    {
        list($result, $target) = $this->authenticate($request, $acl);
        if($result !== true) {
            return $this->invokeFailure($request, $response);
        }
        $this->target = $target;
        return $next($request, $response);
    }

    /**
     * apply authenticate rule to route
     *
     * @param null|string|string[] $acl (optional)
     * @return callable
     */
    public function secure($acl = null)
    {
        $auth = $this;
        return function(Request $request, Response $response, callable $next) use (&$auth, $acl) {
            return $auth->intercept($request, $response, $next, $acl);
        };
    }

    /**
     * get authenticated target
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request (optional)
     * @return mixed
     */
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
        return isset($_SESSION[$this->sessionKey]) ? $_SESSION[$this->sessionKey]: null;
    }

    protected function invokeFailure(Request $request, Response $response)
    {
        return call_user_func($this->failure, $request, $response);
    }


}
