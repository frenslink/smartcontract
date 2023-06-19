require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.2",
  networks: {
    canhlinh: {
      url: `http://45.32.108.128:8545`,
      accounts: ["9bccec53c5c3a1640dbc4bb926651d24611d07fb2aef9024f296bf0f8d90bfdd"]
    }
  }
};
