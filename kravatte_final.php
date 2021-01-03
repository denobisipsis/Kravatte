<?
class Kravatte
{
/*
Kravatte Achouffe Cipher Suite: Encryption, Decryption, and Authentication Tools based on the Farfalle modes

Based on Python implementation with minor changes
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
	
*/
/*
Keccap
*/		   					
    function rotLeft64($lane, $biShift) 
    	{		
	$byShift    = floor($biShift/8);		
	$lane       = substr($lane,-$byShift).substr($lane,0,-$byShift);		
	$biShift   %= 8;		
	$carry      = 0;
	for ($i = 0; $i < 8; $i++) 
		{		
		$temp     = ord($lane[$i]) << $biShift;
		$lane[$i] = chr($temp & 0xff | $carry);
		$carry    = $temp >> 8;		
		}	
	$lane[0] = chr(ord($lane[0]) | $carry);	
	return $lane;		
	}
	
    function SHR_64($x,$n)
    	{
	// mimics python numpy >>
	
	$resto = chr(ord($x[7]) >> $n);
	$x     = self::rotLeft64($x,64-$n);				
	$x[7]  = $x[7] & $resto;
	return $x;	    
	}
		    			       
    function Theta(&$lanes)
    	{	
	for ($x=0;$x<5;$x++) 				
		$C[$x]=$lanes[$x] ^ $lanes[$x+5] ^ $lanes[$x+10] ^ $lanes[$x+15] ^ $lanes[$x+20];
			
	for ($x=0;$x<5;$x++) 
		{	
		$D=$C[($x+4)%5] ^ self::rotLeft64($C[($x+1)%5],1);
		for ($y=0;$y<25;$y+=5) 			
			$lanes[$x+$y]^= $D;			
		}   
	}		
   function Ro_Pi(&$lanes)
	{
	$x=1;$y=0;
	$actual=$lanes[1]; 
	for ($t=0;$t<24;$t++) 
		{
		[$x,$y]=[$y,(2*$x+3*$y)%5];
		$pos=$x+5*$y;		
		[$actual,$lanes[$pos]]=[$lanes[$pos],self::rotLeft64($actual,(($t+1)*($t+2)/2)%64)];
		}
	}
    function Ji(&$lanes)
    	{
	for ($y=0;$y<25;$y+=5) 
		{			
		$temp = array_slice($lanes,$y,5);
		for ($x=0;$x<5;$x++) 			
			$lanes[$x+$y]=$temp[$x] ^ ((~ $temp[($x+1)%5])&$temp[($x+2)%5]);		
		}
	}
    function Iota(&$lanes,$round)
    	{
	$LFSRstate = [
	"0110100","0110011","1001111","0001101","1000010","0010111"];
		
	$RCC = [
	"\1\0\0\0\0\0\0\0",
	"\2\0\0\0\0\0\0\0",
	"\x8\0\0\0\0\0\0\0",
	"\x80\0\0\0\0\0\0\0",
	"\0\x80\0\0\0\0\0\0",
	"\0\0\0\x80\0\0\0\0",
	"\0\0\0\0\0\0\0\x80"];

	for ($j=0;$j<7;$j++) 
		if ($LFSRstate[$round][$j]) $lanes[0] ^= $RCC[$j];		
	}
			
    function keccak_p($state) 
    	{			
	for ($round=0;$round<6;$round++) 
		{			
		self::Theta($state);		
		self::Ro_Pi($state);			
		self::Ji($state);		
		self::Iota($state,$round);	
		}
	return $state;	
	}	

/*		
Kravatte
*/
		    
    function k_key($key)
    	{
        $len 	       = strlen($key);
        $key_pad       = self::pad_10($key, $len + (200 - ($len % 200)));	
	$this->kra_key = self::keccak_p(str_split($key_pad,8));	
    	}

    function reset_state()
    	{
        $this->roll_key      = $this->kra_key;
	$this->collector     = str_split(str_repeat("\0",200),8);
	$this->digest_active = False;
	$this->new_collector = True;
	$this->digest 	     = "";	    
	}
    
    function reord_lane(&$lane,$indice)
    	{
	$temp           = $lane[$indice];
	for ($i=$indice;$i<$indice+4;$i++)$lane[$i]=$lane[$i+1];
	$lane[$indice+4]=$temp;		    
	}
				    		          
    function roll_compress($state)
    	{
	// rolling function rollc
	
        /*$COMPRESS_ROW_REORDER = [[0, 0, 0, 0, 1],
                                 [1, 1, 1, 1, 2],
                                 [2, 2, 2, 2, 3],
                                 [3, 3, 3, 3, 4],
                                 [4, 4, 4, 4, 0]];  
        $COMPRESS_COLUMN_REORDER = [[0, 1, 2, 3, 4],
                                    [0, 1, 2, 3, 4],
                                    [0, 1, 2, 3, 4],
                                    [0, 1, 2, 3, 4],
                                    [0, 1, 2, 3, 4]];*/	
				    
	self::reord_lane($state,20);
	
	$h1        = self::rotLeft64($state[24],7);	
	$h2    	   = self::SHR_64($state[20],3);
			
        $state[24] = $h1 ^ $state[20] ^ $h2;	
        return     $state;			
    	}
	    
    function roll_expand($state)
    	{
	//  rolling function rolle
	
        /*$EXPAND_ROW_REORDER =     [[0, 0, 0, 1, 1],
	                           [1, 1, 1, 2, 2],
	                           [2, 2, 2, 3, 3],
	                           [3, 3, 3, 4, 4],
	                           [4, 4, 4, 0, 0]];    
        $EXPAND_COLUMN_REORDER =     [[0, 1, 2, 3, 4],
                                      [0, 1, 2, 3, 4],
                                      [0, 1, 2, 3, 4],
                                      [0, 1, 2, 3, 4],
                                      [0, 1, 2, 4, 4]];*/		
	$lanes     = $state;
	
	self::reord_lane($lanes,15);
	self::reord_lane($lanes,20);
							    		
	$lanes[19] = $lanes[24];
	
	$h1        = self::rotLeft64($state[15],7);	
	$h2        = self::rotLeft64($state[16],18);
	$h3        = self::SHR_64($state[16],1);
			        
	$lanes[24] = $h1 ^ $h2 ^ ($h3 & $state[17]);
        return     $lanes;
    	}
				       			    
    function xorlanes($state,$xor)
    	{	
	for ($i = 0; $i < 25; $i++)		
		$state[$i] = $state [$i] ^ $xor[$i];			
	return $state;		    
	}
			
    function kcollect($stream, $append_bits=0, $append_bit_count=0)
    	{
        if ($this->digest_active)
		{
		$this->roll_key 	= $this->kra_key;
		$this->collector 	= str_split(str_repeat("\0",200),8);
		$this->digest 		= "";
		$this->digest_active 	= False;
		$this->new_collector 	= True;
		}
  
        if ($this->new_collector)		
		$this->new_collector 	= False;		
        else	$this->roll_key         = self::roll_compress($this->roll_key);
	    
        # Pad 
        $length  = strlen($stream);
        $stream  = self::pad_10($stream, $length + (200 - ($length % 200)), $append_bits, $append_bit_count);	
        $nblocks = strlen($stream) /  200;
	$blocks  = str_split($stream,200);

        # Absorb 	
        for ($i=0;$i<$nblocks;$i++)
	    {	
            $block           = self::xorlanes(str_split($blocks[$i],8),$this->roll_key);	      
            $this->collector = self::xorlanes($this->collector , self::keccak_p($block));	    
	    $this->roll_key  = self::roll_compress($this->roll_key);		    
	    }
    	}
	    	     
    function kdigest($size,$short=false)
    	{  
	if (!$this->digest_active)
		{
		if (!$short)      
			$this->collector = self::keccak_p($this->collector);
		$this->roll_key      = self::roll_compress($this->roll_key);
		$this->digest_active = true;
		}
	
	$this->digest="";
	
	if ($size % 200)
        	$full_output = $size + (200 - ($size % 200)); 
	else 	$full_output = $size;

        $nblocks = $full_output / 200;
			
        for ($i=0;$i<$nblocks;$i++)
	    {	   
            $squeeze 		= self::keccak_p($this->collector);
	    $this->digest      .= implode(self::xorlanes($squeeze , $this->roll_key)); 	    
            $this->collector    = self::roll_expand($this->collector);	              
	    }
	
	$this->digest = substr($this->digest,0,$size);
	}

    function pad_10($stream, $block, $append_bits=0, $append_bit_count=0)
    	{    	        
        $length = strlen($stream);
        if ($length == $block)
		return $stream;

        $pad_byte      = (1 << $append_bit_count) | ((2**$append_bit_count - 1) & $append_bits );	 
        $pad_len       = $block - ($length % $block);	
        $padded_bytes  = $stream.chr($pad_byte).str_Repeat("\x00",$pad_len - 1);
        return $padded_bytes;
    	} 
	    		    		
    function mac($key, $message, $output_size)
	{
	self::k_key($key);
	self::reset_state();	
    	self::kcollect($message);    
	self::kdigest($output_size);    	
    	return bin2hex($this->digest);
        }


/*
Kravatte-SANE, an authenticated encryption scheme supporting sessions
*/

    function initialize_history($nonce,$sanse=false)
    	{
	if ($nonce)	    
        	self::kcollect($nonce);
        $this->history_collector = $this->collector;
	$this->history_collector_state 	= $this->new_collector;
        $this->history_key = $this->roll_key;
	if (!$sanse)
        	self::kdigest($this->TAG_SIZE);
        $this->e_attr = 0;
	}

    function append_to_history($message, $pad_bits, $pad_size)
    	{
        self::kcollect($message, $pad_bits, $pad_size);
        $this->history_collector = $this->collector;
        $this->history_key = $this->roll_key;
	$this->history_collector_state = $this->new_collector;
	}
	
    function krestore($sanse=false)
    	{
        $this->collector     = $this->history_collector;  
        $this->roll_key      = $this->history_key;  
	$this->digest        = "";
	$this->digest_active = False;
	if ($sanse)
	$this->new_collector = $this->history_collector_state;	    
	}
		
    function Kravatte_SANE($nonce,$key)
    	{
	$this->TAG_SIZE = 16;
	self::k_key($key);
	self::reset_state();
        self::initialize_history($nonce);
	}
		
    function SANE_PROC($stream,$metadata,$dec=false)
    	{
	self::krestore();		 
        self::kdigest(strlen($stream) + $this->TAG_SIZE);
        $ciphertext = $stream ^ substr($this->digest,$this->TAG_SIZE); 
	self::krestore();
		
        if (strlen($metadata) > 0 or strlen($stream) == 0)
            self::append_to_history($metadata, ($this->e_attr << 1) | 0, 2);
        if (strlen($stream) > 0)
 	    if (!$dec)		
            	self::append_to_history($ciphertext, ($this->e_attr << 1) | 1, 2);
	    else
	    	self::append_to_history($stream, ($this->e_attr << 1) | 1, 2);
	
	$this->e_attr ^= 1;		
        self::kdigest($this->TAG_SIZE);
	return $ciphertext;    
	}
						
    function Kravatte_SANE_enc($plaintext, $metadata)
    	{
	$ciphertext = self::SANE_PROC($plaintext,$metadata);           
        return [bin2hex($ciphertext), bin2hex($this->digest)];
	}

    function Kravatte_SANE_dec($ciphertext, $metadata, $validation_tag)
    	{
	$plaintext  = self::SANE_PROC($ciphertext,$metadata,true);
        return [bin2hex($plaintext), bin2hex($this->digest) == bin2hex($validation_tag) ? "True" : "False"];
	}

/*
Kravatte-SANSE, an authenticated encryption scheme supporting sessions and using the synthetic initial value (SIV) technique
*/
	
    function Kravatte_SANSE($key)
    	{
    	$this->TAG_SIZE = 32;
	self::k_key($key);
	self::reset_state();
        self::initialize_history('',True);
	}
				
    function kravatte_SANSE_enc($plaintext, $metadata)
    	{		
	self::krestore(true);
        if (strlen($metadata) > 0 or strlen($plaintext) == 0)
            self::append_to_history($metadata, ($this->e_attr << 1) | 0, 2);

        if (strlen($plaintext) > 0)
	    {
	    self::kcollect($plaintext, ($this->e_attr << 2) | 2 , 3);	    
            self::kdigest($this->TAG_SIZE);
            $tag = $this->digest;
	    self::krestore(true);           
	    self::kcollect($tag, ($this->e_attr << 2) | 3 , 3);
	    self::kdigest(strlen($plaintext));
	    $ciphertext = $plaintext ^ $this->digest;             
	    self::krestore(true);
	    self::append_to_history($plaintext, ($this->e_attr << 2) | 2, 3);
	    }
        else
	    {
            $ciphertext = '';
            self::kdigest($this->TAG_SIZE);
            $tag = $this->digest;
	    }
	
	$this->e_attr ^= 1;
           
        return [bin2hex($ciphertext), bin2hex($tag)];
	}

    function kravatte_SANSE_dec($ciphertext, $metadata, $validation_tag)
    	{
	self::krestore(true);
        if (strlen($metadata) > 0 or strlen($ciphertext) == 0)
            self::append_to_history($metadata, ($this->e_attr << 1) | 0, 2);

        if (strlen($ciphertext) > 0)
	    {
	    self::kcollect($validation_tag, ($this->e_attr << 2) | 3 , 3);	    
            self::kdigest(strlen($ciphertext));
            $plaintext = $ciphertext ^ $this->digest; 
            self::krestore(true);
            self::append_to_history($plaintext, ($this->e_attr << 2) | 2, 3);
	    }
        else	    
            $plaintext = '';
	    	
	self::kdigest($this->TAG_SIZE);
	$this->e_attr ^= 1;

        return [bin2hex($plaintext), bin2hex($this->digest) == bin2hex($validation_tag) ? "True" : "False"];
	}


/*

Kravatte-WBC, a wide-block cipher for authenticated encryption with minimal expansion

The Farfalle construction reminds of the keyed sponge construction, with most efficient
version the full-width keyed sponge. It differs in that the keyed sponge is
strictly serial while Farfalle consists of two main layers that are by themselves parallel

 Wide block cipher
 
 There are use cases where it would be practical to have a block cipher with a custom
 block size, or where the block size is adaptable to the task at hand and that supports
 next to the key an additional diversification parameter, called a tweak. Examples include
 disk encryption, where the block size would equal the size of sectors. Another example
 is encryption in the Tor anonymity network
 
 It takes as input a secret key K, an arbitrary-length plaintext P and an arbitrary-length
 tweak W and returns a ciphertext C of same length as the plaintext. It performs a 4-round
 Feistel network to the plaintext
 
*/
	
    function Kravatte_WBC($block_size, $tweak='', $key)
    	{
    	$this->SPLIT_THRESHOLD = 398;
	self::k_key($key);
	self::reset_state();
        self::Kravatte_split($block_size);
        $this->tweak = $tweak;
	}

    function Kravatte_split($message_size)
    	{
        if ($message_size <= $this->SPLIT_THRESHOLD)
            $nL = ceil($message_size / 2);
        else
	    {
            $q = floor((($message_size + 1) / 200)) + 1;
            $x = floor(log($q - 1,2));
            $nL = (($q - (2**$x)) * 200) - 1;
	    }
        $this->size_L = $nL;
        $this->size_R = $message_size - $nL;
	}

    function L_xord(&$L,$R)
    	{
	self::kcollect($this->tweak);
	self::kcollect($R, 1, 1);
	self::kdigest($this->size_L);
	$L ^= $this->digest;	    
	}

    function R_xore(&$R,$L)
    	{
	self::kcollect($L, 0, 1);
	self::kdigest(min(200, $this->size_R), True);
	$e_digest = $this->digest.str_Repeat("\x0",$this->size_R - strlen($this->digest));
	$R ^= $e_digest;	    
	}

    function L_xore(&$L,$R)
    	{
        self::kcollect($R, 1, 1);
        self::kdigest(min(200, $this->size_L), True);
        $e_digest = $this->digest.str_repeat("\x0",$this->size_L - strlen($this->digest));
        $L ^= $e_digest;	    
	}

    function R_xord(&$R,$L)
    	{
        self::kcollect($this->tweak);
        self::kcollect($L, 0, 1);
        self::kdigest($this->size_R);
        $R ^= $this->digest;	    
	}
	
    function Kravatte_WBC_enc($message)
    	{
        $L = substr($message,0,$this->size_L);
        $R = substr($message,$this->size_L);

        self::R_xore($R,$L);
        self::L_xord($L,$R);
        self::R_xord($R,$L);
        self::L_xore($L,$R);

        return bin2hex($L.$R);
	}

    function Kravatte_WBC_dec($message)
    	{
        $L = substr($message,0,$this->size_L);
        $R = substr($message,$this->size_L);

        self::L_xore($L,$R);
        self::R_xord($R,$L);
        self::L_xord($L,$R);
        self::R_xore($R,$L);

        return bin2hex($L.$R);
	}

/*
A (tweakable) wide block cipher can be converted to an authenticated encryption scheme
by applying a very simple mode [34]. The metadata is used as tweak and as encipherment
input one uses the plaintext with some agreed verifiable redundancy, such as 8 bytes
equal to zero appended to the end. The cryptogram is the encipherment output. One
can authenticate the cryptogram by verifying that the decipherment output ends in the
agreed fixed string. This verification process can be performed before full decipherment
is completed, allowing for early rejection of unauthentic cryptograms
*/

	
    function Kravatte_WBC_AE($block_size, $key)
    	{
    	$this->WBC_AE_TAG_LEN = 16;
	self::Kravatte_WBC($block_size+$this->WBC_AE_TAG_LEN, '', $key);
	}

    function Kravatte_WBC_AE_enc($message, $metadata)
    	{
        $this->tweak = $metadata;  
        $pad	     = $message.str_repeat("\x00",$this->WBC_AE_TAG_LEN);
        return self::Kravatte_WBC_enc($pad);
	}
			
    function Kravatte_WBC_AE_dec($message, $metadata)
    	{
        $L = substr($message,0,$this->size_L);
        $R = substr($message,$this->size_L);
        $this->tweak = $metadata;

        self::L_xore($L,$R);	
        self::R_xord($R,$L);
	
	$valid_plaintext = False;
        if ($this->size_R >= 200 + $this->WBC_AE_TAG_LEN)
		{
	        if (substr($R,-$this->WBC_AE_TAG_LEN) == str_Repeat("\x0",$this->WBC_AE_TAG_LEN))
                	$valid_plaintext = True;
		
		self::L_xord($L,$R);		
		self::R_xore($R,$L);
		}
        else
		{
		self::L_xord($L,$R);
                self::R_xore($R,$L);
		
	        if (substr($L.$R,-$this->WBC_AE_TAG_LEN) == str_Repeat("\x0",$this->WBC_AE_TAG_LEN))
                	$valid_plaintext = True;
	    	}
        return [bin2hex(substr($L.$R,0,-$this->WBC_AE_TAG_LEN)), $valid_plaintext];
	}
	
/*
simple pseudo-random number generator built from the Kravatte PRF primitive
*/	
	
    function KravatteOracle($seed, $key)
    	{
	self::k_key($key);
	self::reset_state();        
        self::seed_generator($seed);
	}

    function seed_generator($seed)
    	{
        self::kcollect($seed);
	}

    function random($output_size)
    	{
        self::kdigest($output_size);
        return bin2hex($this->digest);
	}
}
