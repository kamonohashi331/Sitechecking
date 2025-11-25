<?php
header('Content-Type: application/json');

$ip = $_SERVER['REMOTE_ADDR'];
$response = ['ip' => $ip, 'status' => 'fail'];

if (function_exists('curl_init')) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "http://ip-api.com/json/{$ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $apiResponse = curl_exec($ch);
    curl_close($ch);
    
    $ipInfo = json_decode($apiResponse, true);
    
    if ($ipInfo && isset($ipInfo['status'])) {
        $response = array_merge($response, $ipInfo);
    }
}

echo json_encode($response);
?>