
const cxx = require('./cxx')().then((mod) => {
  var demangleCxx =  mod.cwrap('cxx', 'string', ['string']);
  console.log(demangleCxx("_Z29api_internal_launch_ipykernelP7_objectS0_S0_"));
});
