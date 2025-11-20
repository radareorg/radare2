import tryToCatch from 'try-to-catch';
import js from './js.js';
import html from './html.js';
import css from './css.js';
import img from './img.js';

const minifiers = [
    js,
    css,
    html,
    img,
];

export default async (data, options) => {
    let error;
    let result = data;
    
    for (const minify of minifiers) {
        [error, result] = await tryToCatch(minify, data, options);
        
        if (!error)
            break;
    }
    
    return result;
};
