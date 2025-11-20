/* сжимаем код через clean-css */
import assert from 'node:assert';
import Clean from 'clean-css';

/**
 * minify css data.
 *
 * @param data
 * @param userOptions - (optional) object that may contain a `css` key with an object of options
 */
export default (data, userOptions) => {
    assert(data);
    
    const options = userOptions?.css || {};
    
    const {styles, errors} = new Clean(options).minify(data);
    
    const [error] = errors;
    
    if (error)
        throw error;
    
    return styles;
};
