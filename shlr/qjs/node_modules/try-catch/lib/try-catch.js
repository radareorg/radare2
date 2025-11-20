'use strict';

module.exports = (fn, ...args) => {
    try {
        return [null, fn(...args)];
    } catch(e) {
        return [e];
    }
};

