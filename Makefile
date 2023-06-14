compile:
	npx hardhat compile

flatten:
	./node_modules/.bin/poa-solidity-flattener ./contracts/Frens.sol

deploy:
	npx hardhat run --network canhlinh scripts/deploy.js
