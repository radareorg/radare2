'use strict';

const {pathToFileURL} = require('url');
const readjson = require('readjson');
const tryToCatch = require('try-to-catch');

const {assign} = Object;
const isFn = (a) => typeof a === 'function';
const isObject = (a) => typeof a === 'object';

const maybeFrozenFunction = (a) => !isFn(a) ? a : function(...args) {
    return a.apply(this, args);
};

const maybeFrozenObject = (a) => !isObject(a) ? a : assign({}, a);

const importWithExt = async (a, ext = '') => await import(`${a}${ext}`);
const extensions = [
    '.js',
    '.cjs',
    '.mjs',
];

module.exports.createSimport = (url) => {
    url = url.includes('file://') ? url : pathToFileURL(url);
    
    return async (name) => {
        let resolved = name;
        const isRelative = /^\./.test(name);
        
        if (isRelative) {
            resolved = new URL(name, url);
        }
        
        if (/\.json$/.test(resolved))
            return await readjson(resolved);
        
        if (/\.(js|mjs|cjs)$/.test(name)) {
            const processed = resolved.href || `file://${resolved}`;
            const imported = await import(processed);
            
            return buildExports(imported);
        }
        
        let imported;
        let error;
        
        if (/^[@a-z]/.test(name)) {
            imported = await importWithExt(resolved);
        }
        
        if (!imported)
            [error, imported] = await importAbsolute(resolved);
        
        if (error)
            throw error;
        
        return buildExports(imported);
    };
};

async function importAbsolute(resolved) {
    let error;
    let imported;
    
    for (const ext of extensions) {
        [error, imported] = await tryToCatch(importWithExt, resolved, ext);
        
        if (imported)
            break;
    }
    
    return [error, imported];
}

function buildExports(imported) {
    let {default: exports = {}} = imported;
    
    exports = maybeFrozenFunction(exports);
    exports = maybeFrozenObject(exports);
    
    return assign(exports, imported);
}

