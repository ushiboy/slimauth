# Slim用認証ミドルウェア

Slimフレームワーク用の**非公式**認証ミドルウェアです。

アプリケーションのルートごとに認証と認可の設定を適用します。

アプリケーションのモデルの実装に特別な制約を必要としません。


## 使い方

#### ミドルウェアの登録

PHPのセッションを開始し、SlimアプリケーションにSlimAuth\Authを登録します。

SlimAuth\Authのコンストラクタに認証の対象を返すクロージャを設定します。
クロージャがnullを返すと、認証エラー(403)となります。


```php
<?php
session_start();

$app = new \Slim\App([
    'auth' => function($c) {
        return new SlimAuth\Auth(function($id) {
            return User::findOne($id);
        });
    }
]);
```

#### ルートの設定

保護するルートにsecureメソッドで設定を行います。

```php
<?php
$auth = $app->getContainer()->get('auth');

$app->get('/private', function ($request, $response) {
    $response->getBody()->write('OK');
    return $response;
})->add($auth->secure());
```

#### セッションの認証

ログインなどでpermitメソッドを実行し、セッションを認証済みにします。

permitの引数で渡した値がコンストラクタで設定したクロージャの引数になります。

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

#### セッションの認証破棄

ログアウトなどでclearメソッドを実行し、セッションの認証を解除します。

```php
<?php
$app->get('/logout', function ($request, $response) {
    $this->get('auth')->clear();
    return $response->withRedirect('/', 301);
});
```

## 使い方（拡張）

#### ACLによる認可

コンストラクタの第2引数にcheckAclオプションで認可用のクロージャを設定します。

クロージャの引数には認証対象と、ルートごとに設定したACLのリストが渡されます。
クロージャでtrue以外の値を返すと、認可エラーとなります。

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

認可を必要とするルートにsecureメソッドで必要なACLを設定します。

```php
<?php
$auth = $app->getContainer()->get('auth');

$app->get('/admin', function ($request, $response) {
    $response->getBody()->write('OK');
    return $response;
})->add($auth->secure(['admin', 'superuser']));
```

#### 独自認証エラー

コンストラクタの第2引数にfailureオプションでクロージャを設定します。
クロージャの引数でリクエストとレスポンスを受け取り、レスポンスを返します。

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

## サンプル

次のコマンドでサンプルを起動します。

```bash
$ php -S localhost:8080 -t example
```
