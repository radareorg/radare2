import {minify} from '@putout/minify';
import assert from 'node:assert';

/**
 * minify js data.
 *
 * @param data
 * @param userOptions - (optional) object that may contain a `js` key with an object of options
 */
export default async (data, userOptions) => {
    assert(data);
    
    const options = userOptions?.js || {};
    
    if (options.type === 'terser') {
        const {terser} = options;
        const {minify} = await import('terser');
        const {code} = await minify(data, terser);
        
        return code;
    }
    
    return await minify(data, options);
};
