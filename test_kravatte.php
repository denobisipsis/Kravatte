<?
	include "kravatte_final.php";
	
	function xtrae($key,$vector,$x="")
		{
		$k  = explode(",",explode('])',explode("$key = $x"."bytes([",$vector)[1])[0]);		
		$zk = "";foreach ($k as $m) $zk .=@explode("0x",trim($m))[1];
		return pack("H*",$zk);				
		}
		
	$x=new Kravatte;

	// Test Vectors

	$server = "http://raw.githubusercontent.com/inmcm/kravatte/master/tests";
	
	$fvectors = ["mac"];

	foreach ($fvectors as $f)
		{
		$count = 0;
		echo "Kravatte $f ";
		$vectors = file_get_contents("$server/test_kravatte_$f.py");
		$vectors = explode("def test_",$vectors);

		foreach (array_slice(array_slice($vectors,1),0,-1) as $vector)
			{
			$count++;				
			$type   = explode('(',explode('kravatte_',$vector)[1])[0];		
			$size   = explode("_",explode("(",$vector)[0]); $size = $size[sizeof($size)-1];
				    
			$zk	= xtrae("my_key",$vector);			    
			$zm	= xtrae("my_message",$vector);							
			$out    = bin2hex(xtrae("real_output",$vector));	
			
			$res    = $x->mac($zk,$zm, $size);
		
			if (($res != $out))
				die("$count Bad");			
			}
		echo "OK $count tested\n";
		}

	$fvectors = ["sane"];

	foreach ($fvectors as $f)
		{
		$count = 0;
		echo "Kravatte $f ";
		$vectors = file_get_contents("$server/test_kravatte_$f.py");
		$vectors = explode("def test_kravatte",$vectors);

		foreach (array_slice($vectors,1) as $vector)
			{
			$count++;	
			$type = explode('(',explode('SANE_',$vector)[1])[0];
					    
			$zk			= xtrae("my_key",$vector);			    
			$zm			= xtrae("my_message",$vector);
			$meta			= xtrae("my_metadata",$vector);
			$nonce			= xtrae("my_nonce",$vector);			
			$output_ciphertext	= bin2hex(xtrae("output_ciphertexts",$vector,"["));
			$output_tag		= bin2hex(xtrae("output_tags",$vector,"["));
			
			$x->Kravatte_SANE($nonce,$zk);
			
			[$cipher,$tag] = $x->Kravatte_SANE_enc($zm, $meta);
			
			if (($cipher != $output_ciphertext) or ($tag != $output_tag))
				die("$count Bad");			
			}
		echo "OK $count tested\n";
		}
				
	$fvectors = ["sanse"];

	foreach ($fvectors as $f)
		{
		$count=0;
		echo "Kravatte $f ";
		$vectors=file_get_contents("$server/test_kravatte_$f.py");
		$vectors=explode("def test_kravatte",$vectors);

		foreach (array_slice($vectors,1) as $vector)
			{
			$count++;	
			$type=explode('(',explode('SANSE_',$vector)[1])[0];
		
			$zk			= xtrae("my_key",$vector);			    
			$zm			= xtrae("my_message",$vector);
			$meta			= xtrae("my_metadata",$vector);			
			$output_ciphertext	= bin2hex(xtrae("output_ciphertexts",$vector,"["));
			$output_tag		= bin2hex(xtrae("output_tags",$vector,"["));
			
			$x->Kravatte_SANSE($zk);
			
			[$cipher,$tag] = $x->Kravatte_SANSE_enc($zm, $meta);
			
			if (($cipher != $output_ciphertext) or ($tag != $output_tag))
				die("$count Bad");			
			}
		echo "OK $count tested\n";
		}
				
	$fvectors = ["wbc"];

	foreach ($fvectors as $f)
		{
		$count=0;
		echo "Kravatte $f ";
		$vectors=file_get_contents("$server/test_kravatte_$f.py");
		$vectors=explode("def test_kravatte",$vectors);

		foreach (array_slice($vectors,2) as $vector)
			{
			$count++;	
			$type=explode('(',explode('WBC_',$vector)[1])[0];
				    
			$zk			= xtrae("my_key",$vector);			    
			$zm			= xtrae("my_message",$vector);
			$tweak			= xtrae("my_tweak",$vector);					
			$output_ciphertext	= bin2hex(xtrae("real_ciphertext",$vector));
			
			$x->Kravatte_WBC(strlen($zm), $tweak,$zk);
			
			$cipher = $x->Kravatte_WBC_enc($zm);
			
			if (($cipher != $output_ciphertext))
				die("$count Bad");			
			}
		echo "OK $count $f tested\n";
		}
		
	$fvectors = ["wbc_ae"];

	foreach ($fvectors as $f)
		{
		$count=0;
		echo "Kravatte $f ";
		$vectors=file_get_contents("$server/test_kravatte_$f.py");
		$vectors=explode("def test_kravatte",$vectors);

		foreach (array_slice($vectors,1) as $vector)
			{
			$count++;	
			$type=explode('(',explode('WBC_AE_',$vector)[1])[0];		

			$zk			= xtrae("my_key",$vector);			    
			$zm			= xtrae("my_message",$vector);
			$meta			= xtrae("my_metadata",$vector);					
			$output_ciphertext	= bin2hex(xtrae("real_ciphertext",$vector));
						
			$x->Kravatte_WBC_AE(strlen($zm), $zk);
			
			$cipher = $x->Kravatte_WBC_AE_enc($zm,$meta);
			
			if (($cipher != $output_ciphertext))
				die("$count Bad");			
			}
		echo "OK $count $f tested\n";
		}
				
	echo "Kravatte oracle ";
	$vectors=file_get_contents("$server/test_kravatte_oracle.py");
	$vectors=explode("def test_kravatte",$vectors);

	foreach (array_slice($vectors,1) as $vector)
		{	
		$type=explode('(',explode('random_oracle_',$vector)[1])[0];

		$zk			= xtrae("my_key",$vector);			    
		$zm			= xtrae("my_message",$vector);				
		$real			= bin2hex(xtrae("real_output",$vector));

	        $x->KravatteOracle($zm, $zk);
	
	        $index_ref = [[0, 1], [200, 202], [400, 404], [600, 608], [800, 816], [1000, 1032],
	                     [1200, 1264], [1400, 1528], [1600, 1856], [2000, 2512], [2600, 3624],
	                     [3800, 5848]];
	
	        for ($h=0;$h<12;$h++)
		    {
	            $k   = 2**$h;
	            $res = $x->random($k);
	            [$start, $stop] = $index_ref[$h];
	            $m   = substr($real,$start*2,$stop*2-$start*2);
		    
			if (($m != $res))
				die("$k Bad");
		    }			
		}
	echo "OK \n\n";