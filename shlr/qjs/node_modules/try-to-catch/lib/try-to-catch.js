'use strict';

module.exports = async (fn, ...args) => {
    check(fn);
    
    try {
        return [null, await fn(...args)];
    } catch(e) {
        return [e];
    }
};

function check(fn) {
    if (typeof fn !== 'function')
        throw Error('fn should be a function!');
}

