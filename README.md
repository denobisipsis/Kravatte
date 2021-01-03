# Kravatte
PHP-Kravatte Achouffe Cipher Suite: Encryption, Decryption, and Authentication Tools based on the Farfalle modes

Based on this Python implementation with minor changes
https://github.com/inmcm/kravatte

Kravatte is a high-speed instance of Farfalle based on Keccak-p[1600] permutations, 
claimed to resist against classical and quantum adversaries. Modes for authentication, 
encryption and authenticated encryption are defined accordingly.

https://keccak.team/2017/updated_farfalle_kravatte.html
https://eprint.iacr.org/2016/1188.pdf

It pass all tests from https://github.com/inmcm/kravatte/tree/master/tests

2021 @denobisipsis

$x=new Kravatte;

MAC

	$x->mac('Supersecreto', 'Et in Arcadia ego', 64)

SANE

	$x->Kravatte_SANE($nonce,$key);
	
	$cipher = $x->Kravatte_SANE_enc($message, $metadata);
	
	[$cipher, $val]
	
	$x->Kravatte_SANE($nonce,$key);
	
	$plain = $x->Kravatte_SANE_dec(pack("H*",$cipher[0]), $meta, pack("H*",$cipher[1]));
	
	[$message, $val]
  
SANSE

	$x->Kravatte_SANSE($key);
	
	$cipher = $x->Kravatte_SANSE_enc($message, $metadata);
	
	[$cipher, $val]
	
	$x->Kravatte_SANSE($key);
	
	$plain = $x->Kravatte_SANSE_dec(pack("H*",$cipher[0]), $meta, pack("H*",$cipher[1]));
	
	[$message, $val]

WBC

	$x->Kravatte_WBC(strlen($message), $tweak,$key);
	
	$cipher = $x->Kravatte_WBC_enc($message);
		
	$x->Kravatte_WBC(strlen($message), $tweak,$key);
	
	$message = $x->Kravatte_WBC_dec(pack("H*",$cipher));
	

WBC_AE

	$x->Kravatte_WBC_AE(strlen($message), $key);
	
	$cipher = $x->Kravatte_WBC_AE_enc($message,$metadata);

	$x->Kravatte_WBC_AE(strlen($message),$key);
	
	$plain = $x->Kravatte_WBC_AE_dec(pack("H*",$cipher),$metadata);
	
Oracle

  $x->KravatteOracle($message, $key);

	$x->random($size);
	
