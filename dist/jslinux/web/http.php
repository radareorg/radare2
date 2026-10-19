<?php
// radare2 - LGPL - Copyright 2026 - pancake

const R2_HTTP_MAX_REQUEST = 2 * 1024 * 1024;
const R2_HTTP_MAX_RESPONSE = 16 * 1024 * 1024;

function reply(int $status, array $value): void {
	header('Content-Type: application/json');
	header('Cache-Control: no-store');
	header('X-Content-Type-Options: nosniff');
	http_response_code($status);
	echo json_encode($value, JSON_UNESCAPED_SLASHES);
	exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	header('Allow: POST');
	reply(405, ['error' => 'Use POST with a JSON request']);
}

$upstream = getenv('R2_HTTP_UPSTREAM');
$token = getenv('R2_HTTP_TOKEN');
if (!$upstream || !$token) {
	reply(503, ['error' => 'Relay is not configured']);
}
$address = parse_url($upstream);
if (!$address || !in_array($address['scheme'] ?? '', ['http', 'https'], true)
		|| empty($address['host']) || isset($address['user']) || isset($address['pass'])
		|| isset($address['query']) || isset($address['fragment'])
		|| preg_match('/[\x00-\x20\x7f\\\\]/', $upstream)) {
	reply(503, ['error' => 'Invalid relay upstream configuration']);
}
if (!extension_loaded('curl')) {
	reply(503, ['error' => 'PHP cURL extension is required']);
}

$input = file_get_contents('php://input', false, null, 0, R2_HTTP_MAX_REQUEST + 1);
if ($input === false || strlen($input) > R2_HTTP_MAX_REQUEST) {
	reply(413, ['error' => 'Request exceeds 2 MiB']);
}
$request = json_decode($input);
if (!is_object($request)) {
	reply(400, ['error' => 'Expected a JSON object']);
}
if (!isset($request->token) || !is_string($request->token)
		|| !hash_equals($token, $request->token)) {
	reply(403, ['error' => 'Invalid relay token']);
}

$method = $request->method ?? 'GET';
$path = $request->path ?? '/';
$fields = $request->headers ?? '';
$data = $request->data ?? '';
if (!in_array($method, ['GET', 'POST'], true) || !is_string($path)
		|| !is_string($fields) || !is_string($data)) {
	reply(400, ['error' => 'Expected GET/POST and string path, headers and data']);
}
if ($path === '' || $path[0] !== '/' || substr($path, 0, 2) === '//'
		|| preg_match('/[\x00-\x20\x7f\\\\#]/', $path)) {
	reply(400, ['error' => 'Expected an upstream path beginning with /']);
}
if ($method === 'GET' && $data !== '') {
	reply(400, ['error' => 'GET cannot carry request data']);
}

$allowedHeaders = [
	'accept', 'content-type', 'authorization', 'x-api-key', 'x-goog-api-key',
	'anthropic-version', 'anthropic-beta', 'openai-organization', 'openai-project',
];
$headers = [];
foreach (explode("\n", $fields) as $field) {
	if ($field === '') {
		continue;
	}
	$colon = strpos($field, ':');
	if ($colon === false || preg_match('/[\x00-\x1f\x7f]/', $field)) {
		reply(400, ['error' => 'Invalid upstream header']);
	}
	$name = strtolower(substr($field, 0, $colon));
	if (!in_array($name, $allowedHeaders, true) || isset($headers[$name])) {
		reply(400, ['error' => 'Unsupported or duplicate upstream header']);
	}
	$headers[$name] = $name . ': ' . trim(substr($field, $colon + 1));
}

$body = '';
$tooLarge = false;
$curl = curl_init(rtrim($upstream, '/') . $path);
curl_setopt_array($curl, [
	CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
	CURLOPT_FOLLOWLOCATION => false,
	CURLOPT_CONNECTTIMEOUT => 10,
	CURLOPT_TIMEOUT => 120,
	CURLOPT_HTTPHEADER => array_values($headers),
	CURLOPT_ENCODING => '',
	CURLOPT_WRITEFUNCTION => function ($handle, string $chunk) use (&$body, &$tooLarge): int {
		$length = strlen($chunk);
		if (strlen($body) + $length > R2_HTTP_MAX_RESPONSE) {
			$tooLarge = true;
			return 0;
		}
		$body .= $chunk;
		return $length;
	},
]);
if ($method === 'POST') {
	curl_setopt($curl, CURLOPT_POST, true);
	curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
}
$ok = curl_exec($curl);
$status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
$error = curl_errno($curl);
curl_close($curl);
if ($ok === false) {
	if ($tooLarge) {
		reply(502, ['error' => 'Upstream response exceeds 16 MiB']);
	}
	reply($error === CURLE_OPERATION_TIMEDOUT ? 504 : 502, ['error' => 'Upstream request failed']);
}

// Keep upstream errors and binary bodies intact through TinyEMU's XHR transport.
reply(200, ['status' => $status, 'body' => base64_encode($body), 'encoding' => 'base64']);
