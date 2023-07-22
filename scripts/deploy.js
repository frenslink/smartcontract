// scripts/deploy.js
const forwarder = require( '../build/gsn/Forwarder').address

async function main () {
    const Frens = await ethers.getContractFactory('Frens');
    console.log('Deploying Frens...');
    const frens = await Frens.deploy(forwarder);
    await frens.deployed();
    console.log('Box deployed to:', frens.address);
  }
  
  main()
    .then(() => process.exit(0))
    .catch(error => {
      console.error(error);
      process.exit(1);
    });