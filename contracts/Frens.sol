// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@opengsn/contracts/src/ERC2771Recipient.sol";
import "@opengsn/contracts/src/interfaces/IERC2771Recipient.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";


contract Frens is 
    IERC721Receiver, 
    IERC1155Receiver, 
    ERC2771Recipient, 
    ReentrancyGuard, 
    Ownable 
    {
    using SafeERC20 for IERC20;

    enum TokenType{ Native, ERC20, ERC721, ERC1155 }
    uint256 public lockBlocks = 100; 
    address[] public whiteListTokens;
    
    mapping(TokenType => uint256) public gasLimitConfigs;
    uint256 public gasPrice = 0;
    uint256 public constant minGasLimit = 21000;

    uint256 public constant defaultProtocolFee = 0.0005 ether;
    mapping(TokenType => uint256) public protocolFeeConfigs;
    uint256 public protocolBalance = 0;
    uint256 public maxBatchLinks = 100;

    struct Deposit {
        uint256     tokenAmount; // Amount of the token
        address     tokenAddress; // Address of the token. 0x0 for ETH
        TokenType   tokenType;  // TokenType following by the enumations
        uint256     tokenId; // ID of the token if erc721 or erc1155
        address     pubKey; // Key to lock the token
        address     sender; // Address of the sender
        uint256     blockNo; // The block of deposit
        bool        claimed;  // indicates this deposit been claimed
    }

    Deposit[] public deposits;

    event DepositEvent(uint256 indexed _index, uint8 indexed _tokenType, address _tokenAddress, uint256 _tokenAmount, address indexed _sender);
    event ClaimEvent(uint256 indexed _index, uint8 indexed _tokenType, address _tokenAddress, uint256 _tokenAmount, address indexed _recipient);
    event ClaimCrossChainEvent(uint256 indexed _index, uint8 indexed _tokenType, uint256 _tokenAmount, uint256 _fee, address indexed _recipientAddress, bytes callResult);
    event WithdrawEvent(address indexed _payee, uint256 _amount);


    constructor(address forwarder) {
        _setTrustedForwarder(forwarder);
        gasPrice = 40 gwei;
        gasLimitConfigs[TokenType.Native] = minGasLimit;
        gasLimitConfigs[TokenType.ERC20] = 65000;
        gasLimitConfigs[TokenType.ERC721] = 300000;
        gasLimitConfigs[TokenType.ERC1155] = 300000;
    }

    function setTrustedForwarder(address _forwarder) external onlyOwner {
        _setTrustedForwarder(_forwarder);
    }

    function setLockBlocks(uint256 _lockBlocks) external onlyOwner {
        lockBlocks = _lockBlocks;
    }

    function setWhiteListTokens(address[] memory _tokenAddress) external  onlyOwner {
        whiteListTokens = _tokenAddress;
    }

    function isAllowDepositToken(address _tokenAddress) public view returns(bool){
        if (whiteListTokens.length == 0) {
            return true;
        }
        for (uint256 i = 0; i< whiteListTokens.length; i++) {
            if (whiteListTokens[i] == _tokenAddress) {
                return true;
            }
        }
        return false;
    }

    function setGasLimit(TokenType _tokenType, uint256 _gasLimit) external onlyOwner {
        require(uint8(_tokenType) < 4, "INVALID CONTRACT TYPE");
        require(_gasLimit >= minGasLimit, "INVALID GAS LIMIT");
        gasLimitConfigs[_tokenType] = _gasLimit;
    }

    function setGasPrice(uint256 _gasPrice) external onlyOwner {
        gasPrice = _gasPrice;
    }

    function setProtocolFee(TokenType _tokenType, uint256 _protocolFee) external onlyOwner {
        require(uint8(_tokenType) < 4, "INVALID CONTRACT TYPE");
        require(_protocolFee > 0, "INVALID PROCOL FEE");
        protocolFeeConfigs[_tokenType] = _protocolFee;
    }

    function setMaxBatchLinks(uint256 _maxBatchLinks) external onlyOwner {
        maxBatchLinks = _maxBatchLinks;
    }

    function estimateGasFeeForClaim(TokenType _tokenType) public view returns(uint256) {
        uint256 gasLimit = gasLimitConfigs[_tokenType];
        if (gasLimit == 0) {
            gasLimit = minGasLimit;
        }
        return gasLimit * gasPrice;
    }

    function estimateProtocolFee(TokenType _tokenType) public view returns(uint256) {
        uint256 fee = protocolFeeConfigs[_tokenType];
        if (fee == 0) {
            return defaultProtocolFee;
        }
        return fee;
    }

    function estimateDepositFee(TokenType _tokenType) public view returns(uint256) {
        return estimateProtocolFee(_tokenType) + estimateGasFeeForClaim(_tokenType);
    }

    function makeDeposit(
        TokenType _tokenType,
        address _tokenAddress,
        uint256 _tokenAmount,
        uint256 _tokenId,
        address _pubKey
    ) external payable returns (uint256) {
        require(uint8(_tokenType) < 4, "INVALID CONTRACT TYPE");
        require(isAllowDepositToken(_tokenAddress), "TokenAddress is not allowed");
        uint256 _depositFee = estimateDepositFee(_tokenType);
        require(msg.value >= _depositFee, "NOT ENOUGH PROTOCOL FEE");

        if (_tokenType == TokenType.Native) {
            _tokenAmount = msg.value - _depositFee;
            require(_tokenAddress == address(0), "tokenAddress must be zero");
            protocolBalance += _depositFee;
        } else {
            require(_tokenAddress != address(0), "tokenAddress must not be zero");
            protocolBalance += msg.value;
        }

        require(_tokenAmount > 0, "YOU CAN NOT SEND ZERO TOKEN");
        processDeposit(_tokenType, _tokenAddress, _tokenAmount, _tokenId);
        return insertDeposit(_tokenType, _tokenAddress, _tokenAmount, _tokenId, _pubKey);
    }

    function processDeposit(
        TokenType _tokenType,
        address _tokenAddress,
        uint256 _tokenAmount,
        uint256 _tokenId
        ) private {
        if (_tokenType == TokenType.ERC20) {
            IERC20 token = IERC20(_tokenAddress);
            require(
                token.balanceOf(_msgSender()) >= _tokenAmount,
                "INSUFFICIENT TOKEN BALANCE"
            );
            require(
                token.allowance(_msgSender(), address(this)) >= _tokenAmount,
                "INSUFFICIENT ALLOWANCE"
            );
            require(
                token.transferFrom(_msgSender(), address(this), _tokenAmount),
                "TRANSFER FAILED. CHECK ALLOWANCE & BALANCE"
            );
        } else if (_tokenType == TokenType.ERC721) {
            _tokenAmount = 1;
            IERC721 token = IERC721(_tokenAddress);
            token.safeTransferFrom(
                _msgSender(),
                address(this),
                _tokenId,
                "Internal transfer"
            );
        } else if (_tokenType == TokenType.ERC1155) {
            IERC1155 token = IERC1155(_tokenAddress);
            token.safeTransferFrom(
                _msgSender(),
                address(this),
                _tokenId,
                _tokenAmount,
                "Internal transfer"
            );
        }
    }

    function insertDeposit(
        TokenType _tokenType,
        address _tokenAddress,
        uint256 _tokenAmount,
        uint256 _tokenId,
        address _pubKey
    ) private returns (uint256) {
        address _sender = _msgSender();
        // add deposit
        deposits.push(
            Deposit({
                tokenType: _tokenType,
                tokenAddress: _tokenAddress,
                tokenAmount: _tokenAmount,
                tokenId: _tokenId,
                pubKey: _pubKey,
                sender: _sender,
                blockNo: block.number,
                claimed: false
            })
        );
        // emit the deposit event
        emit DepositEvent(
            deposits.length - 1, 
            uint8(_tokenType),
            _tokenAddress,
            _tokenAmount,
            _sender
        );
        return deposits.length - 1;
    }

    function makeBatchDeposits(
        TokenType _tokenType,
        address _tokenAddress,
        uint256 _tokenAmount,
        address[] memory _pubKeys
    ) external payable returns (uint256[] memory) {
        require(_pubKeys.length > 0, "pubKeys can not be empty");
        require(_pubKeys.length <= maxBatchLinks, "pubKeys maximum reached");
        require(uint8(_tokenType) < 2, "INVALID CONTRACT TYPE");
        require(isAllowDepositToken(_tokenAddress), "TokenAddress is not allowed");

        uint256 _depositFee = _pubKeys.length * estimateDepositFee(_tokenType);
        require(msg.value >= _depositFee, "NOT ENOUGH PROTOCOL FEE");

        if (_tokenType == TokenType.Native) {
            _tokenAmount = msg.value - _depositFee;
            require(_tokenAddress == address(0), "tokenAddress must be zero");
            protocolBalance += _depositFee;
        } else {
            require(_tokenAddress != address(0), "tokenAddress must not be zero");
            protocolBalance += msg.value;
        }

        require(_tokenAmount > 0, "YOU CAN NOT SEND ZERO TOKEN");
        processDeposit(_tokenType, _tokenAddress, _tokenAmount, 0);

        uint256 amountPerDeposit = _tokenAmount/_pubKeys.length;
        uint256[] memory depositIndexes = new uint256[](_pubKeys.length);
        for (uint256 i = 0; i< _pubKeys.length; i++) {
            depositIndexes[i] = insertDeposit(_tokenType, _tokenAddress, amountPerDeposit, 0, _pubKeys[i]);
        }
        return depositIndexes;
    }

    /**
     * @notice Erc721 token receiver function
     * @dev These functions are called by the token contracts when a token is sent to this contract
     * @dev If calldata is "Internal transfer" then the token was sent by this contract and we don't need to do anything
     * @dev Otherwise, calldata needs a 20 byte pubkey
     * @param _operator address operator requesting the transfer
     * @param _from address address which previously owned the token
     * @param _tokenId uint256 ID of the token being transferred
     * @param _data bytes data to send along with a safe transfer check
     */
    function onERC721Received(
        address _operator,
        address _from,
        uint256 _tokenId,
        bytes calldata _data
    ) external pure override returns (bytes4) {
        if (keccak256(_data) == keccak256("Internal transfer")) {
            return this.onERC721Received.selector;
        } else {
            revert("NOT ALLOW RECEIVING ERC721");
        }
    }

    /**
        @notice Erc1155 token receiver function
        @dev These functions are called by the token contracts when a token is sent to this contract
        @dev If calldata is "Internal transfer" then the token was sent by this contract and we don't need to do anything
        @dev Otherwise, calldata needs 20 bytes pubKey
        @param _operator address operator requesting the transfer
        @param _from address address which previously owned the token
        @param _tokenId uint256 ID of the token being transferred
        @param _value uint256 amount of tokens being transferred
        @param _data bytes data passed with the call
     */
    function onERC1155Received(
        address _operator,
        address _from,
        uint256 _tokenId,
        uint256 _value,
        bytes calldata _data
    ) external pure override returns (bytes4) {
        if (keccak256(_data) == keccak256("Internal transfer")) {
            // if data is "Internal transfer", nothing to do, return
            return this.onERC1155Received.selector;
        } else {
            revert("NOT ALLOW RECEIVING ERC721");
        }
    }

    /**
     * @notice Erc1155 token receiver function
     * @dev These functions are called by the token contracts when a set of tokens is sent to this contract
     * @dev If calldata is "Internal transfer" then the token was sent by this contract and we don't need to do anything
     * @param _operator address operator requesting the transfer
     * @param _from address address which previously owned the token
     * @param _ids uint256[] IDs of each token being transferred (order and length must match _values array)
     * @param _values uint256[] amount of each token being transferred (order and length must match _ids array)
     * @param _data bytes data forwarded from the caller
     * @dev _data needs to contain array of 20 byte pubKeys (length must match _ids and _values arrays)
     */
    function onERC1155BatchReceived(
        address _operator,
        address _from,
        uint256[] calldata _ids,
        uint256[] calldata _values,
        bytes calldata _data
    ) external pure override returns (bytes4) {
        if (keccak256(_data) == keccak256("Internal transfer")) {
            // if data is "Internal transfer", nothing to do, return
            return this.onERC1155BatchReceived.selector;
        } else {
            revert("NOT ALLOW RECEIVING ERC721");
        }
    }

    /**
     * @notice Function to claim a deposit. Withdraws the deposit to the recipient address.
     * @dev _recipientAddressHash is hash("\x19Ethereum Signed Message:\n32" + hash(_recipientAddress))
     * @dev The signature should be signed with the private key corresponding to the public key stored in the deposit
     * @dev We don't check the unhashed address for security reasons. It's preferable to sign a hash of the address.
     * @param _index uint256 index of the deposit
     * @param _recipientAddress address of the recipient
     * @param _recipientAddressHash bytes32 hash of the recipient address (prefixed with "\x19Ethereum Signed Message:\n32")
     * @param _signature bytes signature of the recipient address (65 bytes)
     * @return bool true if successful
     */
    function claimDeposit(
        uint256 _index,
        address _recipientAddress,
        bytes32 _recipientAddressHash,
        bytes memory _signature
    ) external returns (bool) {
        // check that the deposit exists and that it isn't already withdrawn
        require(_index < deposits.length, "DEPOSIT INDEX DOES NOT EXIST");
        Deposit memory _deposit = deposits[_index];
        require(_deposit.claimed == false, "DEPOSIT ALREADY WITHDRAWN");

        verifyHash(keccak256(abi.encodePacked(_recipientAddress)), _recipientAddressHash);
        verifySignature(_recipientAddressHash, _signature, _deposit.pubKey);

        // Deposit request is valid. Withdraw the deposit to the recipient address.
        if (_deposit.tokenType == TokenType.Native) {
            (bool success,) = _recipientAddress.call{value: _deposit.tokenAmount}("");
            require(success, "Failed to transfer native token");
        } else if (_deposit.tokenType == TokenType.ERC20) {
            IERC20 token = IERC20(_deposit.tokenAddress);
            token.safeTransfer(_recipientAddress, _deposit.tokenAmount);
        } else if (_deposit.tokenType == TokenType.ERC721) {
            IERC721 token = IERC721(_deposit.tokenAddress);
            token.transferFrom(
                address(this),
                _recipientAddress,
                _deposit.tokenId
            );
        } else if (_deposit.tokenType == TokenType.ERC1155) {
            IERC1155 token = IERC1155(_deposit.tokenAddress);
            token.safeTransferFrom(
                address(this),
                _recipientAddress,
                _deposit.tokenId,
                _deposit.tokenAmount,
                ""
            );
        }

        // emit the withdraw event
        emit ClaimEvent(
            _index,
            uint8(_deposit.tokenType),
            _deposit.tokenAddress,
            _deposit.tokenAmount,
            _recipientAddress
        );

        // set deposit as claimed
        deposits[_index].claimed = true;
        return true;
    }

    // sender can withdraw deposited assets after some blocks
    function claimBySender(uint256 _index) external {
        require(_index < deposits.length, "DEPOSIT INDEX DOES NOT EXIST");
        Deposit memory _deposit = deposits[_index];
        require(block.number >= _deposit.blockNo + lockBlocks ,"SENDER MUST WAIT AFTER SOME BLOCKS TO WITHDRAW");
        require(_deposit.sender == _msgSender(),"MUST BE SENDER TO WITHDRAW");
        require(_deposit.claimed == false, "DEPOSIT ALREADY WITHDRAWN");

        // handle eth deposits
        if (_deposit.tokenType == TokenType.Native) {
            payable(_msgSender()).transfer(_deposit.tokenAmount);
        } else if (_deposit.tokenType == TokenType.ERC20) {
            IERC20 token = IERC20(_deposit.tokenAddress);
            token.transfer(_msgSender(), _deposit.tokenAmount);
        } else if (_deposit.tokenType == TokenType.ERC721) {
            IERC721 token = IERC721(_deposit.tokenAddress);
            token.transferFrom(
                address(this),
                _msgSender(),
                _deposit.tokenId
            );
        } else if (_deposit.tokenType == TokenType.ERC1155) {
            IERC1155 token = IERC1155(_deposit.tokenAddress);
            token.safeTransferFrom(
                address(this),
                _msgSender(),
                _deposit.tokenId,
                _deposit.tokenAmount,
                ""
            );
        }

        // emit the withdraw event
        emit ClaimEvent(
            _index,
            uint8(_deposit.tokenType),
            _deposit.tokenAddress,
            _deposit.tokenAmount,
            _msgSender()
        );

        // set deposit as claimed
        deposits[_index].claimed = true;
    }


    function withdrawProfit(address payable payee) external onlyOwner {
        require(protocolBalance > 0, "No profit");
        payee.transfer(protocolBalance);
        emit WithdrawEvent(payee, protocolBalance);
        protocolBalance = 0;
    }


    /**
     * @notice Claim cross-chain through Squid
     */
    function claimCrossChain(
        uint256 _index,
        address _recipientAddress, 
        bytes memory _squidData,
        uint256 _squidValue,
        address _squidRouter,
        bytes32 _hash,
        bytes memory _signature
    ) external payable nonReentrant returns (bool) {
        require(_index < deposits.length, "DEPOSIT INDEX DOES NOT EXIST");
        Deposit memory _deposit = deposits[_index];
        require(_deposit.claimed == false, "DEPOSIT ALREADY WITHDRAWN");
        require(uint8(_deposit.tokenType) < 2, "NO SUPPORTED CONTRACT TYPE");

        verifyHash(keccak256(abi.encodePacked(_recipientAddress, _squidRouter, _squidData, _squidValue)), _hash);
        verifySignature(_hash, _signature, _deposit.pubKey);

        // execute the cross-chain transfer
        bool success = false;
        bytes memory callResult;
        if (_deposit.tokenType == TokenType.Native) {
            uint256 feeAmount = _squidValue - _deposit.tokenAmount;
            require(msg.value >= feeAmount, "INSUFFICIENT FEE SENT");
            uint256 amountToSend = _deposit.tokenAmount + msg.value;
            require(amountToSend >= _squidValue, "INSUFFICIENT PAYMENT");
            (success, callResult) = payable(_squidRouter).call{value: amountToSend}(_squidData);

            emit ClaimCrossChainEvent(
                _index, uint8(_deposit.tokenType), _deposit.tokenAmount, feeAmount, _recipientAddress, callResult
            );
        } else if (_deposit.tokenType == TokenType.ERC20) {
            require(msg.value >= _squidValue, "INSUFFICIENT PAYMENT");
            // for ERC20 tokens this value is needed as this pays for the execution
            IERC20 token = IERC20(_deposit.tokenAddress);
            token.approve(_squidRouter, _deposit.tokenAmount);
            (success, callResult) = payable(_squidRouter).call{value: _squidValue}(_squidData);

            emit ClaimCrossChainEvent(
                _index, uint8(_deposit.tokenType), _deposit.tokenAmount, _squidValue, _recipientAddress, callResult
            );
        }
        require(success, "FAILED TO CLAIM OVER CROSS CHAIN");

        // set deposit as claimed
        deposits[_index].claimed = true;
        return true;
    }

    function getDepositCount() external view returns (uint256) {
        return deposits.length;
    }

    function getDepositsByAddress(address _address) external view returns (Deposit[] memory) {
        Deposit[] memory _deposits = new Deposit[](deposits.length);
        uint256 count = 0;
        for (uint256 i = 0; i < deposits.length; i++) {
            if (deposits[i].sender == _address) {
                _deposits[count] = deposits[i];
                count++;
            }
        }
        return _deposits;
    }

    /**
        @notice supportsInterface function
        @dev ERC165 interface detection
        @param _interfaceId bytes4 the interface identifier, as specified in ERC-165
        @return bool true if the contract implements the interface specified in _interfaceId
     */
    function supportsInterface(bytes4 _interfaceId)
        external
        pure
        override
        returns (bool)
    {
        return
            _interfaceId == type(IERC165).interfaceId ||
            _interfaceId == type(IERC721Receiver).interfaceId ||
            _interfaceId == type(IERC1155Receiver).interfaceId || 
            _interfaceId == type(IERC2771Recipient).interfaceId;
    }

    function _msgSender() internal view override(Context, ERC2771Recipient)
        returns (address sender) {
        sender = ERC2771Recipient._msgSender();
    }

    function _msgData() internal view override(Context, ERC2771Recipient)
        returns (bytes calldata) {
        return ERC2771Recipient._msgData();
    }

    function verifyHash(bytes32 _message ,bytes32 _messageHash) public pure returns (bool)  {
        require(ECDSA.toEthSignedMessageHash(_message) == _messageHash,"HASHES DO NOT MATCH");
        return true;
    }

    function verifySignature(bytes32 _hash, bytes memory signature, address signer) public pure returns (bool) {
        require(ECDSA.recover(_hash, signature) == signer, "WRONG SIGNATURE");
        return true;
    }
}
