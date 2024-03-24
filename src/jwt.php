<?php

/*

	Packgist rafsouza/php-jwt v1.0 

	Autor: Rafael Souza Rodrigues Santos
	Github: https://github.com/rafaelsouzars

	Descrição: Este componente fornece métodos básicos para manipulação do JWT como: criação e validação do token.
	Além dessas funcionalidades o componente também manipula arquivos .env para armazenamento das JWK 'Json Web Key'
	
	- Features futuras:
		- Gerar o refresh token.
		- Gerenciar o tempo de expiração
		- Manipular cookies

*/

namespace RafSouza\Src;

class JWT {	
	
	private $header;
	private $payload;
	private $signature;
	private $jwk;
	
	private const HEADER = [
			'alg'=>'HS256',
			'typ'=>'JWT'
		];
	
	// Cria uma nova instância e inicia o atributo privado 'header' com o cabeçalho padrão do JWT
	function __construct() {
		$this->header = json_encode(self::HEADER);
	}

	// Destrutor
	function __destruct() {
		$this->payload = null;
		$this->jwk = null;
	}
	
	/* Getters e Setters*/
	// Retorna o payload do JWT
	public function getPayload() {
		return $this->payload;
	}
	
	// Adicionar chave secreta para criptografia
	public function setJWK($key) {
		$this->jwk = $key;
	}
	
	/* Métodos privados da classe */
	// Codificador base64Url para PHP
	private function base64url_encode($data){
		if(isset($data)){
			$b64 = base64_encode($data);
			$url = strtr($b64,'+/','-_');
			return rtrim($url, '=');
		}
	}
	
	// Decodificador base64Url para PHP
	private function base64url_decode($data, $strict = false){
		$b64 = strtr($data, '-_','+/');
		
		return base64_decode($b64, $strict);
	}
	
	// Valida a assinatura do token
	private function validarAssinatura($b64Header,$b64Payload,$b64Signature) {	// Validation signature JWS	
		$this->payload = null;
		$signature = hash_hmac('sha256', $b64Header . '.' . $b64Payload, $this->jwk); 

		if ($signature == $this->base64Url_decode($b64Signature)) {
			$this->payload = $this->base64Url_decode($b64Payload);
			return true;
		} else {
			return false;
		}
		
		//return ($signature == $this->base64Url_decode($b64Signature))?true:false;
	}
	
	// Carregar arquivo .env contendo o JWK
	private function carregarArquivoEnv($arquivo) {
		try {
			if (!file_exists($arquivo)) { // Verifica se o arquivo existe
				throw new Exception('Exception: Arquivo .env não encontrado!!!'); // Caso não exista, gera uma mensagem de erro
			}
			else {
				$linhas = file($arquivo, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES); // Carrega o arquivo para leitura
				
				foreach($linhas as $linha) { // Lê linha por linha
					if (strpos(trim($linha), '#') === 0) {
						continue; // Pula a lina de comentário
					}
					
					list($chave, $valor) = explode('=', $linha, 2); // Gera um array com duas posições e cria uma lista com chave e valor
					$chave = trim($chave);
					$valor = trim($valor);
					
					if (!array_key_exists($chave, $_ENV)) { // Verifica se a chave não existe para que seja criada
						putenv(sprintf('%s=%s', $chave, $valor));
						$_ENV[$chave] = $valor;
						
						$this->jwk = $valor;												
					}
				}
			}
		}
		catch (Throwable $e) {
			echo 'Erro: Falha ao carregar arquivo .env: ' . $e->getMessage() . ' \\n ';
		}
		finally {
			
		}
	}
	
	/* Métodos públicos da classe */
	// Criar o token
	public function createToken($token) {		
		try{
			if(isset($token) and isset($this->jwk)){ // Verifica as variáveis 'token' e 'jwk' foram carregadas
				$json = json_encode($token);
				$payload = $json;
				$signature = hash_hmac('sha256',$this->base64url_encode($this->header) . '.' . $this->base64url_encode($payload), $this->jwk); // Assinatura do JWT
				$jwt = $this->base64url_encode($this->header) . '.' . $this->base64url_encode($payload) . '.' . $this->base64url_encode($signature);
				return $jwt;
			}else{
				throw new Exception('Token ou JWK não foram iniciados corretamente!!!');
			}
		}
		catch (Throwable $e) {
			echo 'Erro: ' . $e->getMessage() . '\\n';
		}			
	}
	
	// Carregar chave armazenada no arquivo .env
	public function loadEnvJWK($file) {
		$this->carregarArquivoEnv($file);
	}
	
	// Validar o token
	public function validationToken($authorization) {
		try {
			if(isset($authorization)) {
				$serializedToken = str_replace('Bearer ','', $authorization); // Retira o 'Bearer', e o espaço,  do cabeçalho HTTP 'Authorization'				
				$partsToken = explode('.', $serializedToken); // Divide o JWT em três partes			
				return $this->validarAssinatura($partsToken[0],$partsToken[1],$partsToken[2]); // Valida a assinatura do JWT		
			}
		}
		catch(Throwable $e) {
			echo 'Erro: ' . $e->getMessage() . '\\n';
		}
	}			

}

?>