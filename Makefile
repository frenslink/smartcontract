compile:
	npx hardhat compile

flatten:
	./node_modules/.bin/poa-solidity-flattener ./contracts/Frens.sol
	./node_modules/.bin/poa-solidity-flattener ./contracts/tokens/usdc.sol
	./node_modules/.bin/poa-solidity-flattener ./contracts/tokens/usdt.sol

runtest:
	npx hardhat test