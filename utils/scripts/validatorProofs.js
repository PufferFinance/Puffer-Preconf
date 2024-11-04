
import { generateValidatorInclusionProof} from '../libs/beaconUtils.js';

// example of how to generate a validator inclusion proof for validator 912203 at slot 9000000
generateValidatorInclusionProof(9000000, 912203).then(console.log).catch(console.error);
