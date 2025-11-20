import {findUp} from 'find-up';
import _readjson from 'readjson';

export async function readOptions(overrides = {}) {
    const {
        readjson = _readjson,
        find = findUp,
    } = overrides;
    
    const optionsPath = await find('.minify.json');
    
    if (!optionsPath)
        return {};
    
    return readjson(optionsPath);
}
