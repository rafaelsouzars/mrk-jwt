# Mrk-Jwt

![Static Badge](https://img.shields.io/badge/version-0.1-green) ![Static Badge](https://img.shields.io/badge/status-beta-yellow)

*__Descrição__*: Este componente PHP fornece métodos básicos para manipulação do JWT como: criação e validação do token.
Além dessas funcionalidades o componente também manipula arquivos .env para armazenamento das JWK 'Json Web Key'.

### Criar um JWT

```PHP
require '../vendor/autoload.php';

use Rafsouza\MrkJwt\jwt;

$jwt = new JWT();

$jwt->setJWK('123');

$token = [
	'sub' => 'john',
	'iss' => 'mrk',
	'iat' => '10123030'
];

echo $jwt->createToken($token);

```
ou

```PHP
require '../vendor/autoload.php';

use Rafsouza\MrkJwt\jwt;

$jwt = new JWT();

//$jwt->loadEnvJWK(dirname(__FILE__,2) .'\.env');
$jwt->loadEnvJWK('../.env');

$token = [
	'sub' => 'john',
	'iss' => 'mrk',
	'iat' => '10123030'
];

echo $jwt->createToken($token);

```

### Validar um JWT

```PHP
require '../vendor/autoload.php';

use Rafsouza\MrkJwt\jwt;

$authorization = $_SERVER["HTTP_AUTHORIZATION"];

$jwt = new JWT();
$jwt->setJWK('123');

echo $jwt->validationToken($authorization);

```

ou

```PHP
require '../vendor/autoload.php';

use Rafsouza\MrkJwt\jwt;

$authorization = $_SERVER["HTTP_AUTHORIZATION"];

$jwt = new JWT();
//$jwt->loadEnvJWK(dirname(__FILE__,2) .'\.env');
$jwt->loadEnvJWK('../.env');

echo $jwt->validationToken($authorization);

```