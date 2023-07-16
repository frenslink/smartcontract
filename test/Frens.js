const { expect } = require("chai");
const hre = require("hardhat");
const {
  loadFixture,
  time,
} = require("@nomicfoundation/hardhat-toolbox/network-helpers");

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

describe("Frens", function () {
  async function deployFrens() {
    const frens = await ethers.deployContract("Frens", [ZERO_ADDRESS]);

    return { frens };
  }

  it("Should set the right GSN provider", async function () {
    const { frens } = await loadFixture(deployFrens);

    // assert that the value is correct
    expect(await frens.getTrustedForwarder()).to.equal(ZERO_ADDRESS);
    const [owner, addr1] = await ethers.getSigners();
    await frens.setTrustedForwarder(addr1);
    expect(await frens.getTrustedForwarder()).to.equal(addr1.address);
  });

  it("Should set the right lockBlocks", async function () {
    const { frens } = await loadFixture(deployFrens);
    expect(await frens.lockBlocks()).to.equal(12);
    await frens.setLockBlocks(13);
    expect(await frens.lockBlocks()).to.equal(13);
  });

  it("Should set the right gasLimits", async function () {
    const { frens } = await loadFixture(deployFrens);
    expect(await frens.gasLimits(ZERO_ADDRESS)).to.equal(0);
    await frens.setGasLimit(ZERO_ADDRESS, 30000);
    expect(await frens.gasLimits(ZERO_ADDRESS)).to.equal(30000);
  });

  it("Should set the right default gas limit", async function () {
    const { frens } = await loadFixture(deployFrens);
    expect(await frens.defaultGasLimit()).to.equal(21000);
    await frens.setDefaultGasLimit(30000);
    expect(await frens.defaultGasLimit()).to.equal(30000);
  });

  it("Should set the right protocol fee", async function () {
    const { frens } = await loadFixture(deployFrens);
    expect(await frens.protocolFee()).to.equal(ethers.parseEther("0.0005", "ether"));
    const newEther = ethers.parseEther("0.0001", "ether")
    await frens.setProtocolFee(newEther);
    expect(await frens.protocolFee()).to.equal(newEther);
  });

  it("Should set the right min gas price", async function () {
    const { frens } = await loadFixture(deployFrens);
    expect(await frens.protocolFee()).to.greaterThan(0);
    await frens.setMinGasPrice(10000);
    expect(await frens.minGasPrice()).to.equal(10000);
  });

  it("Should estimate right fee", async function () {
    const { frens } = await loadFixture(deployFrens);

    const gasLimit = await frens.defaultGasLimit();
    const gasPrice = await frens.minGasPrice();
    const protocolFee = await frens.protocolFee();
    expect(await frens.estimateFee(ZERO_ADDRESS)).to.equal(protocolFee + (gasLimit*gasPrice));
  });

  it("Should make deposit", async function () {
    const { frens } = await loadFixture(deployFrens);
    const tokenAddress = "0x0000000000000000000000000000000000000000"
    const contractType = 0
    const amount = 0
    const tokenId = 0
    const pubKey20 = "0x0000000000000000000000000000000000000000"

    const fee = await frens.estimateFee(ZERO_ADDRESS);
    const sentValue = ethers.parseEther("0.0123", "ether")
    expect(await frens.getDepositCount()).to.equal(0);
    const [owner] = await ethers.getSigners();
    const tx = await frens.makeDeposit(tokenAddress, contractType, amount, tokenId, pubKey20, {value: sentValue + fee});
    const rc = await tx.wait()
    const c = await frens.getDepositCount();
    expect(c).to.equal(1);
    const args = rc.logs[0].args
    expect(args[0]).to.equal(c-BigInt(1));
    expect(args[1]).to.equal(contractType);
    expect(args[2]).to.equal(tokenAddress);
    expect(args[3]).to.equal(sentValue);
    expect(args[4]).to.equal(owner.address);
  });

  it("Should withdraw sucessfully", async function () {
    const { frens } = await loadFixture(deployFrens);
    const tokenAddress = "0x0000000000000000000000000000000000000000"
    const contractType = 0
    const amount = 0
    const tokenId = 0

    const fee = await frens.estimateFee(ZERO_ADDRESS);
    const sentValue = ethers.parseEther("0.0123", "ether")
    expect(await frens.getDepositCount()).to.equal(0);
    const [_, sender, receipient] = await ethers.getSigners();
    await frens.connect(sender)

    const password = "abcxyz"
    const keys = generateKeysFromString(password)

    const tx = await frens.makeDeposit(tokenAddress, contractType, amount, tokenId, keys.address, {value: sentValue + fee});
    const rc = await tx.wait()
    const args = rc.logs[0].args
    const dIndex = args[0]
    const beforeWithdrawBalance = await ethers.provider.getBalance(receipient.address)
    
    const addressHash = await ethers.solidityPackedKeccak256(["address"], [receipient.address])
    const addressHashBinary = await ethers.getBytes(addressHash);
    const addressHashEIP191 = await ethers.hashMessage(addressHashBinary);
    const signature = await signAddress(addressHashBinary, keys.privateKey);
    // console.log(addressHash, addressHashBinary, addressHashEIP191, signature)

    const tx1 = await frens.withdrawDeposit(dIndex, receipient.address, addressHashEIP191, signature);
    const rc1 = await tx1.wait()
    const args1 = rc1.logs[0].args
    expect(args1[0]).to.equal(dIndex);
    expect(args1[1]).to.equal(contractType);
    expect(args1[2]).to.equal(tokenAddress);
    expect(args1[3]).to.equal(sentValue);
    expect(args1[4]).to.equal(receipient.address);
    const afterWithdrawBalance = await ethers.provider.getBalance(receipient.address)
    expect(afterWithdrawBalance).to.equal(beforeWithdrawBalance + sentValue)
  });
});

async function signAddress(addressHashBinary, privateKey) {
  // 2. add eth msg prefix, then hash, then sign
  var signer = new ethers.Wallet(privateKey);
  var signature = await signer.signMessage(addressHashBinary); // this calls ethers.hashMessage and prefixes the hash
  return signature;
}

function generateKeysFromString(string) {
  /* generates a deterministic key pair from an arbitrary length string */
  var privateKey = ethers.keccak256(ethers.toUtf8Bytes(string));
  var wallet = new ethers.Wallet(privateKey);
  var publicKey = wallet.publicKey;

  return {
    address: wallet.address,
    privateKey: privateKey,
    publicKey: publicKey,
  };
}