pragma solidity ^0.5.0;

import "../build/Update_verifier.sol";
import "../build/Withdraw_verifier.sol";

contract IMiMC {
    function MiMCpe7(uint256,uint256) public pure returns(uint256) {}
}

contract IMiMCMerkle {

    uint[16] public zeroCache;
    function getRootFromProof(
        uint256,
        uint256[] memory,
        uint256[] memory
    ) public view returns(uint) {}
    function hashMiMC(uint[] memory) public view returns(uint){}
}

contract ITokenRegistry {
    address public coordinator;
    uint256 public numTokens;
    mapping(address => bool) public pendingTokens;
    mapping(uint256 => address) public registeredTokens;
    modifier onlyCoordinator(){
        assert (msg.sender == coordinator);
        _;
    }
    function registerToken(address tokenContract) public {}
    function approveToken(address tokenContract) public onlyCoordinator{}
}

contract IERC20 {
    function transferFrom(address from, address to, uint256 value) public returns(bool) {}
	function transfer(address recipient, uint value) public returns (bool) {}
}

contract RollupNC is Update_verifier, Withdraw_verifier{

    IMiMC public mimc;
    IMiMCMerkle public mimcMerkle;
    ITokenRegistry public tokenRegistry;
    IERC20 public tokenContract;

    uint256 public currentRoot;
    address public coordinator;
    uint256[] public pendingDeposits;
    uint public queueNumber;
    uint public depositSubtreeHeight;
    uint256 public updateNumber;

    uint256 public BAL_DEPTH = 4;
    uint256 public TX_DEPTH = 2;

    // (queueNumber => [pubkey_x, pubkey_y, balance, nonce, token_type])
    mapping(uint256 => uint256) public deposits; //leaf idx => leafHash
    mapping(uint256 => uint256) public updates; //txRoot => update idx

    event RegisteredToken(uint tokenType, address tokenContract);
    event RequestDeposit(uint[2] pubkey, uint amount, uint tokenType);
    event UpdatedState(uint currentRoot, uint oldRoot, uint txRoot);
    event Withdraw(uint[9] accountInfo, address recipient);

    constructor(
        address _mimcContractAddr,
        address _mimcMerkleContractAddr,
        address _tokenRegistryAddr
    ) public {
        mimc = IMiMC(_mimcContractAddr);
        mimcMerkle = IMiMCMerkle(_mimcMerkleContractAddr);
        tokenRegistry = ITokenRegistry(_tokenRegistryAddr);
        currentRoot = mimcMerkle.zeroCache(BAL_DEPTH);
        coordinator = msg.sender;
        queueNumber = 0;
        depositSubtreeHeight = 0;
        updateNumber = 0;
    }

    modifier onlyCoordinator(){
        assert(msg.sender == coordinator);
        _;
    }

    // params:
    // a: updateProof pi_a[2]
    // b: updateProof pi_b[2][2]
    // c: updateProof pi_c[2]
    // input: updateInput public-input[3] (newRoot, txRoot, oldRoot)
    function updateState(
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[3] memory input
        ) public onlyCoordinator { // permissions management: only Coordinator can update state
        // check: contract RollupNC currentRoot must match with input last param
        require(currentRoot == input[2], "input does not match current root");
        //validate proof

        // a,b,c respectively as pariing G1Point,G2Point,G1Point
        //struct Proof1 {
        //  Pairing.G1Point A;
        //  Pairing.G2Point B;
        //  Pairing.G1Point C;
        //}

        // it call verify1(inputValues, proof) to check proof true or false
        // verify1 params: public-input as inputValues, and Proof1 as proof
        // linear combination vk_x then pairingProd4.
        require(update_verifyProof(a,b,c,input),
        "SNARK proof is invalid");
        // if check proof ok, then update merkle root(input[0])
        currentRoot = input[0];
        // increase idx
        updateNumber++;
        // update txRoot(input[1]) map with idx
        updates[input[1]] = updateNumber;
        // finally emit event for state update
        emit UpdatedState(input[0], input[1], input[2]); //newRoot, txRoot, oldRoot
    }

    // user tries to deposit ERC20 tokens
    // mainly update pendingDeposits queue
    function deposit(
        uint[2] memory pubkey,
        uint amount,
        uint tokenType
    ) public payable { // payable for transfer
      // tokenType0 reserved for coordinator(address/amount/value)
      if ( tokenType == 0 ) {
           require(
			   msg.sender == coordinator,
			   "tokenType 0 is reserved for coordinator");
           require(
			   amount == 0 && msg.value == 0,
			   "tokenType 0 does not have real value");
        } else if ( tokenType == 1 ) { // tokenType1 check balance
           require(
			   msg.value > 0 && msg.value >= amount,
			   "msg.value must at least equal stated amount in wei");
        } else if ( tokenType > 1 ) { // odinary case
            require(
				amount > 0,
				"token deposit must be greater than 0");
            // get tokenType contract and check token transfer parm amount
            address tokenContractAddress = tokenRegistry.registeredTokens(tokenType);
            tokenContract = IERC20(tokenContractAddress);
            require(
                tokenContract.transferFrom(msg.sender, address(this), amount),
                "token transfer not approved"
            );
        }
        // fill depositArray[5]
        uint[] memory depositArray = new uint[](5);
        depositArray[0] = pubkey[0];
        depositArray[1] = pubkey[1];
        depositArray[2] = amount;
        depositArray[3] = 0;
        depositArray[4] = tokenType;
        
        // call IMiMCMerkle contract caculate mimc hash using filled depositArray as input param
        uint depositHash = mimcMerkle.hashMiMC(
            depositArray
        );
        // fill pending Deposits queue and emit an requestDeposit
        pendingDeposits.push(depositHash);
        emit RequestDeposit(pubkey, amount, tokenType);
        queueNumber++;
        uint tmpDepositSubtreeHeight = 0;
        uint tmp = queueNumber;
        // handle remainder part
        // when an odd total number RequestDeposit then 
        // use the last two queue elements as input to cacultate mimc hash again 
        // result as queue second last element and remove the last from the queue
        while(tmp % 2 == 0){
            uint[] memory array = new uint[](2);
            array[0] = pendingDeposits[pendingDeposits.length - 2];
            array[1] = pendingDeposits[pendingDeposits.length - 1];
            pendingDeposits[pendingDeposits.length - 2] = mimcMerkle.hashMiMC(
                array
            );
            removeDeposit(pendingDeposits.length - 1);
            tmp = tmp / 2;
            tmpDepositSubtreeHeight++;
        }
        if (tmpDepositSubtreeHeight > depositSubtreeHeight){
            depositSubtreeHeight = tmpDepositSubtreeHeight;
        }
    }



    // coordinator adds certain number of deposits to balance tree
    // coordinator must specify subtree index in the tree since the deposits
    // are being inserted at a nonzero height
    function processDeposits(
        uint subtreeDepth,
        uint[] memory subtreePosition,
        uint[] memory subtreeProof
    ) public onlyCoordinator returns(uint256){
        uint emptySubtreeRoot = mimcMerkle.zeroCache(subtreeDepth); //empty subtree of height 2
        require(currentRoot == mimcMerkle.getRootFromProof(
            emptySubtreeRoot, subtreePosition, subtreeProof),
            "specified subtree is not empty");
        currentRoot = mimcMerkle.getRootFromProof(
            pendingDeposits[0], subtreePosition, subtreeProof);
        removeDeposit(0);
        queueNumber = queueNumber - 2**depositSubtreeHeight;
        return currentRoot;
    }

    function withdraw(
        uint[9] memory txInfo, //[pubkeyX, pubkeyY, index, toX ,toY, nonce, amount, token_type_from, txRoot]
        uint[] memory position,
        uint[] memory proof,
        address payable recipient,
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c
    ) public{
        // check tokenType, txRoot(exist and match ProofRoot)
        require(txInfo[7] > 0, "invalid tokenType");
        require(updates[txInfo[8]] > 0, "txRoot does not exist");
        uint[] memory txArray = new uint[](8);
        for (uint i = 0; i < 8; i++){
            txArray[i] = txInfo[i];
        }
        uint txLeaf = mimcMerkle.hashMiMC(txArray);
        require(txInfo[8] == mimcMerkle.getRootFromProof(
            txLeaf, position, proof),
            "transaction does not exist in specified transactions root"
        );

        // message is hash of nonce and recipient address
        uint[] memory msgArray = new uint[](2);
        msgArray[0] = txInfo[5];
        msgArray[1] = uint(recipient);
        
        // using (pi_a,pi_b,pi_c) and txInfo to check  proof
        // NOTE: here call verify which verifyingKey is different with verifyingKey1 in update_verifier
        require(withdraw_verifyProof(
            a, b, c,
            [txInfo[0], txInfo[1], mimcMerkle.hashMiMC(msgArray)]
            ),
            "eddsa signature is not valid");

        // if proof ok, transfer token on tokenContract: ETH or ERC20 token
        if (txInfo[7] == 1){
            // ETH
            recipient.transfer(txInfo[6]);
        } else {
            // ERC20
            address tokenContractAddress = tokenRegistry.registeredTokens(txInfo[7]);
            tokenContract = IERC20(tokenContractAddress);
            require(
                tokenContract.transfer(recipient, txInfo[6]),
                "transfer failed"
            );
        }
        // emit an withDraw event to get tx recipient
        emit Withdraw(txInfo, recipient);
    }

    //call methods on TokenRegistry contract

    function registerToken(
        address tokenContractAddress
    ) public {
        tokenRegistry.registerToken(tokenContractAddress);
    }

    function approveToken(
        address tokenContractAddress
    ) public onlyCoordinator {
        tokenRegistry.approveToken(tokenContractAddress);
        emit RegisteredToken(tokenRegistry.numTokens(),tokenContractAddress);
    }

    // helper functions
    function removeDeposit(uint index) internal returns(uint[] memory) {
        require(index < pendingDeposits.length, "index is out of bounds");

        for (uint i = index; i<pendingDeposits.length-1; i++){
            pendingDeposits[i] = pendingDeposits[i+1];
        }
        delete pendingDeposits[pendingDeposits.length-1];
        pendingDeposits.length--;
        return pendingDeposits;
    }
}
