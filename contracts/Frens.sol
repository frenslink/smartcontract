// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@opengsn/contracts/src/ERC2771Recipient.sol";
import "@opengsn/contracts/src/interfaces/IERC2771Recipient.sol";



contract Frens is IERC721Receiver, IERC1155Receiver, ERC2771Recipient, Ownable {
    uint256 public lockBlocks = 12; // 12 blocks
    mapping(address => uint256) public gasLimits;
    uint256 public defaultGasLimit = 21000;
    uint256 public protocolFee = 0.0005 ether;
    uint256 public profit = 0;
    uint256 public minGasPrice = 0;


    struct deposit {
        address pubKey; // Key to lock the token
        uint256 amount; // Amount of the token
        address tokenAddress; // Address of the token. 0x0 for ETH
        uint8 contractType;  // 0 for eth, 1 for erc20, 2 for erc721, 3 for erc1155
        uint256 tokenId; // ID of the token if erc721 or erc1155
        address sender; // Address of the sender
        uint256 depositedAt; // The block of deposit
    }

    deposit[] public deposits;

    event DepositEvent(
        uint256 _index,
        uint8 _contractType,
        address _tokenAddress,
        uint256 _amount,
        address indexed _senderAddress
    );
    event WithdrawEvent(
        uint256 _index,
        uint8 _contractType,
        address _tokenAddress,
        uint256 _amount,
        address indexed _recipientAddress
    );
    event WithdrawnProfit(
        address indexed payee, 
        uint256 weiAmount
    );

    constructor(address forwarder) {
        _setTrustedForwarder(forwarder);
        minGasPrice = tx.gasprice;
    }

    function setTrustedForwarder(address _forwarder) external onlyOwner {
        _setTrustedForwarder(_forwarder);
    }

    function setLockBlocks(uint256 _lockBlocks) external onlyOwner {
        lockBlocks = _lockBlocks;
    }

    function setGasLimit(address _token, uint256 _gasLimit) external onlyOwner {
        gasLimits[_token] = _gasLimit;
    }

    function setDefaultGasLimit(uint256 _gasLimit) external onlyOwner {
        defaultGasLimit = _gasLimit;
    }

    function setProtocolFee(uint256 _protocolFee) external onlyOwner {
        protocolFee = _protocolFee;
    }

    function setMinGasPrice(uint256 _minGasPrice) external onlyOwner {
        minGasPrice = _minGasPrice;
    }

    function estimateFee(address _token) public view returns(uint256) {
        uint256 gasLimit = gasLimits[_token];
        if (gasLimit == 0) {
            gasLimit = defaultGasLimit;
        }
        uint256 gasPrice = minGasPrice > tx.gasprice? minGasPrice:tx.gasprice;
        uint256 withdrawFee = (gasPrice * gasLimit);
        return withdrawFee + protocolFee;
    }

    function makeDeposit(
        address _tokenAddress,
        uint8 _contractType,
        uint256 _amount,
        uint256 _tokenId,
        address _pubKey
    ) external payable returns (uint256) {
        uint256 fee = estimateFee(_tokenAddress);
        require(msg.value >= fee, "NOT ENOUGH PROTOCOL FEE");

        // check that the contract type is valid
        require(_contractType < 4, "INVALID CONTRACT TYPE");

        // handle deposit types
        if (_contractType == 0) {
            _amount = msg.value - fee;
            require(_amount > 0, "YOU CAN NOT SEND ZERO TOKEN");
            profit += fee;
        } else {
            if (_contractType == 1) {
                require(_amount > 0, "YOU CAN NOT SEND ZERO TOKEN");
                // REMINDER: User must approve this contract to spend the tokens before calling this function
                // Unfortunately there's no way of doing this in just one transaction.
                // Wallet abstraction pls

                IERC20 token = IERC20(_tokenAddress);

                // require users token balance to be greater than or equal to the amount being deposited
                require(
                    token.balanceOf(_msgSender()) >= _amount,
                    "INSUFFICIENT TOKEN BALANCE"
                );

                // require allowance to be at least the amount being deposited
                require(
                    token.allowance(_msgSender(), address(this)) >= _amount,
                    "INSUFFICIENT ALLOWANCE"
                );

                // transfer the tokens to the contract
                require(
                    token.transferFrom(_msgSender(), address(this), _amount),
                    "TRANSFER FAILED. CHECK ALLOWANCE & BALANCE"
                );
            } else if (_contractType == 2) {
                // REMINDER: User must approve this contract to spend the tokens before calling this function.
                // alternatively, the user can call the safeTransferFrom function directly and append the appropriate calldata

                IERC721 token = IERC721(_tokenAddress);
                // require(token.ownerOf(_tokenId) == _msgSender(), "Invalid token id");
                token.safeTransferFrom(
                    _msgSender(),
                    address(this),
                    _tokenId,
                    "Internal transfer"
                );
            } else if (_contractType == 3) {
                // REMINDER: User must approve this contract to spend the tokens before calling this function.
                // alternatively, the user can call the safeTransferFrom function directly and append the appropriate calldata

                IERC1155 token = IERC1155(_tokenAddress);
                token.safeTransferFrom(
                    _msgSender(),
                    address(this),
                    _tokenId,
                    _amount,
                    "Internal transfer"
                );
            }

            // adds profit
            profit += msg.value;
        }

        // create deposit
        deposits.push(
            deposit({
                tokenAddress: _tokenAddress,
                contractType: _contractType,
                amount: _amount,
                tokenId: _tokenId,
                pubKey: _pubKey,
                sender: _msgSender(),
                depositedAt: block.timestamp
            })
        );

        // emit the deposit event
        emit DepositEvent(
            deposits.length - 1,
            _contractType,
            _tokenAddress,
            _amount,
            _msgSender()
        );

        // return id of new deposit
        return deposits.length - 1;
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
    ) external override returns (bytes4) {
        if (keccak256(_data) == keccak256("Internal transfer")) {
            // if data is "Internal transfer", nothing to do, return
            return this.onERC721Received.selector;
        } else if (_data.length != 20) {
            // if data is not 20 bytes, revert (don't want to accept and lock up tokens!)
            revert("INVALID CALLDATA");
        }

        // get the params from calldata and make a deposit
        address _tokenAddress = _msgSender();
        uint8 _contractType = 2;
        uint256 _amount = 1;
        address _pubKey = abi.decode(_data, (address));

        // create deposit
        deposits.push(
            deposit({
                tokenAddress: _tokenAddress,
                contractType: _contractType,
                amount: _amount,
                tokenId: _tokenId,
                pubKey: _pubKey,
                sender: _msgSender(),
                depositedAt: block.timestamp
            })
        );

        // emit the deposit event
        emit DepositEvent(
            deposits.length - 1,
            _contractType,
            _tokenAddress,
            _amount,
            _operator
        );

        // return correct bytes4
        return this.onERC721Received.selector;
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
    ) external override returns (bytes4) {
        if (keccak256(_data) == keccak256("Internal transfer")) {
            // if data is "Internal transfer", nothing to do, return
            return this.onERC1155Received.selector;
        } else if (_data.length != 20) {
            // if data is not 20 bytes, revert (don't want to accept and lock up tokens!)
            revert("INVALID CALLDATA");
        }

        // get the params from calldata and make a deposit
        address _tokenAddress = _msgSender();
        uint8 _contractType = 3;
        uint256 _amount = _value;
        address _pubKey;
        _pubKey = abi.decode(_data, (address));

        // create deposit
        deposits.push(
            deposit({
                tokenAddress: _tokenAddress,
                contractType: _contractType,
                amount: _amount,
                tokenId: _tokenId,
                pubKey: _pubKey,
                sender: _msgSender(),
                depositedAt: block.timestamp
            })
        );

        // emit the deposit event
        emit DepositEvent(deposits.length - 1, _contractType, _tokenAddress,  _amount, _from);

        // return correct bytes4
        return this.onERC1155Received.selector;
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
    ) external override returns (bytes4) {
        if (keccak256(_data) == keccak256("Internal transfer")) {
            // if data is "Internal transfer", nothing to do, return
            return this.onERC1155BatchReceived.selector;
        } else if (_data.length != (_ids.length * 20)) {
            // dont accept if data is not 20 bytes per token
            revert("INVALID CALLDATA");
        }

        // get the params from calldata and make a deposit
        address _tokenAddress = _msgSender();
        uint8 _contractType = 4;
        address _pubKey;
        uint256 _amount;
        uint256 _tokenId;

        for (uint256 i = 0; i < _ids.length; i++) {
            _amount = _values[i];
            _tokenId = _ids[i];
            uint256 _offset = i * 20;
            bytes memory _pubKeyBytes = new bytes(20);
            for (uint256 j = 0; j < 20; j++) {
                _pubKeyBytes[j] = _data[_offset + j];
            }
            _pubKey = abi.decode(_pubKeyBytes, (address));

            // create deposit
            deposits.push(
                deposit({
                    tokenAddress: _tokenAddress,
                    contractType: _contractType,
                    amount: _amount,
                    tokenId: _tokenId,
                    pubKey: _pubKey,
                    sender: _msgSender(),
                    depositedAt: block.timestamp
                })
            );

            // emit the deposit event
            emit DepositEvent(
                deposits.length - 1,
                _contractType,
                _tokenAddress,
                _amount,
                _from
            );
        }

        // return correct bytes4
        return this.onERC1155BatchReceived.selector;
    }

    /**
     * @notice Function to withdraw a deposit. Withdraws the deposit to the recipient address.
     * @dev _recipientAddressHash is hash("\x19Ethereum Signed Message:\n32" + hash(_recipientAddress))
     * @dev The signature should be signed with the private key corresponding to the public key stored in the deposit
     * @dev We don't check the unhashed address for security reasons. It's preferable to sign a hash of the address.
     * @param _index uint256 index of the deposit
     * @param _recipientAddress address of the recipient
     * @param _recipientAddressHash bytes32 hash of the recipient address (prefixed with "\x19Ethereum Signed Message:\n32")
     * @param _signature bytes signature of the recipient address (65 bytes)
     * @return bool true if successful
     */
    function withdrawDeposit(
        uint256 _index,
        address _recipientAddress,
        bytes32 _recipientAddressHash,
        bytes memory _signature
    ) external returns (bool) {
        // check that the deposit exists and that it isn't already withdrawn
        require(_index < deposits.length, "DEPOSIT INDEX DOES NOT EXIST");
        deposit memory _deposit = deposits[_index];
        require(_deposit.amount > 0, "DEPOSIT ALREADY WITHDRAWN");
        // check that the recipientAddress hashes to the same value as recipientAddressHash
        require(
            _recipientAddressHash ==
                ECDSA.toEthSignedMessageHash(
                    keccak256(abi.encodePacked(_recipientAddress))
                ),
            "HASHES DO NOT MATCH"
        );
        // check that the signer is the same as the one stored in the deposit
        address depositSigner = getSigner(_recipientAddressHash, _signature);
        require(depositSigner == _deposit.pubKey, "WRONG SIGNATURE");

        // Deposit request is valid. Withdraw the deposit to the recipient address.
        if (_deposit.contractType == 0) {
            /// handle eth deposits
            payable(_recipientAddress).transfer(_deposit.amount);
        } else if (_deposit.contractType == 1) {
            // handle erc20 deposits
            IERC20 token = IERC20(_deposit.tokenAddress);
            token.transfer(_recipientAddress, _deposit.amount);
        } else if (_deposit.contractType == 2) {
            // handle erc721 deposits
            IERC721 token = IERC721(_deposit.tokenAddress);
            token.transferFrom(
                address(this),
                _recipientAddress,
                _deposit.tokenId
            );
        } else if (_deposit.contractType == 3) {
            // handle erc1155 deposits
            IERC1155 token = IERC1155(_deposit.tokenAddress);
            token.safeTransferFrom(
                address(this),
                _recipientAddress,
                _deposit.tokenId,
                _deposit.amount,
                ""
            );
        }

        // emit the withdraw event
        emit WithdrawEvent(
            _index,
            _deposit.contractType,
            _deposit.tokenAddress,
            _deposit.amount,
            _recipientAddress
        );

        // delete the deposit
        delete deposits[_index];

        return true;
    }

    // sender can withdraw deposited assets after some blocks
    function withdrawSender(uint256 _index) external {
        require(_index < deposits.length, "DEPOSIT INDEX DOES NOT EXIST");
        deposit memory _deposit = deposits[_index];
        require(
            block.number >= _deposit.depositedAt + lockBlocks ,
            "SENDER MUST WAIT AFTER SOME BLOCKS TO WITHDRAW"
        );
        require(
            _deposit.sender == _msgSender(),
            "MUST BE SENDER TO WITHDRAW"
        );

        // handle eth deposits
        if (_deposit.contractType == 0) {
            // send eth to sender
            payable(_msgSender()).transfer(_deposit.amount);
        } else if (_deposit.contractType == 1) {
            IERC20 token = IERC20(_deposit.tokenAddress);
            token.transfer(_msgSender(), _deposit.amount);
        } else if (_deposit.contractType == 2) {
            IERC721 token = IERC721(_deposit.tokenAddress);
            token.transferFrom(
                address(this),
                _msgSender(),
                _deposit.tokenId
            );
        } else if (_deposit.contractType == 3) {
            IERC1155 token = IERC1155(_deposit.tokenAddress);
            token.safeTransferFrom(
                address(this),
                _msgSender(),
                _deposit.tokenId,
                _deposit.amount,
                ""
            );
        }

        // emit the withdraw event
        emit WithdrawEvent(
            _index,
            _deposit.contractType,
            _deposit.tokenAddress,
            _deposit.amount,
            _msgSender()
        );

        // delete the deposit
        delete deposits[_index];
    }


    function withdrawProfit(address payable payee) external onlyOwner {
        require(profit > 0, "No profit");
        payee.transfer(profit);
        profit = 0;
        emit WithdrawnProfit(payee, profit);
    }

    /**
     * @notice Gets the signer of a messageHash. Used for signature verification.
     * @dev Uses ECDSA.recover. On Frontend, use secp256k1 to sign the messageHash
     * @dev also remember to prepend the messageHash with "\x19Ethereum Signed Message:\n32"
     * @param messageHash bytes32 hash of the message
     * @param signature bytes signature of the message
     * @return address of the signer
     */
    function getSigner(bytes32 messageHash, bytes memory signature)
        internal
        pure
        returns (address)
    {
        address signer = ECDSA.recover(messageHash, signature);
        return signer;
    }

    /**
     * @notice Simple way to get the total number of deposits
     * @return uint256 number of deposits
     */
    function getDepositCount() external view returns (uint256) {
        return deposits.length;
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
}
