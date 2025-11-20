/* сжимаем код через htmlMinify */
import assert from 'node:assert';
import Minifier from 'html-minifier-terser';

const defaultOptions = {
    removeComments: true,
    removeCommentsFromCDATA: true,
    removeCDATASectionsFromCDATA: true,
    collapseWhitespace: true,
    collapseBooleanAttributes: true,
    removeAttributeQuotes: true,
    removeRedundantAttributes: true,
    useShortDoctype: true,
    removeEmptyAttributes: true,
    /* оставляем, поскольку у нас
     * в элемент fm генерируеться
     * таблица файлов
     */
    removeEmptyElements: false,
    removeOptionalTags: true,
    removeScriptTypeAttributes: true,
    removeStyleLinkTypeAttributes: true,
    
    minifyJS: true,
    minifyCSS: true,
};

/**
 * minify html data.
 *
 * @param data
 * @param userOptions - (optional) object that may contain an `html` key with an object of options
 */
export default (data, userOptions) => {
    assert(data);
    
    const options = {
        ...defaultOptions,
        ...userOptions?.html || {},
    };
    
    return Minifier.minify(data, options);
};
