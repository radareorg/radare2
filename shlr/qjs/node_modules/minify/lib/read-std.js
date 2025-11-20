import {promisify, TextDecoder} from 'node:util';
import process from 'node:process';

export const readStd = async () => {
    if (globalThis.Deno)
        return await denoReadStd();
    
    return await nodeReadStd();
};

export const nodeReadStd = promisify((callback) => {
    const {stdin} = process;
    let chunks = '';
    
    const read = () => {
        const chunk = stdin.read();
        
        if (chunk)
            return chunks += chunk;
        
        stdin.removeListener('readable', read);
        callback(null, chunks);
    };
    
    stdin.setEncoding('utf8');
    stdin.addListener('readable', read);
});

export const denoReadStd = async () => {
    const {Deno} = globalThis;
    
    let chunks = '';
    
    const decoder = new TextDecoder();
    
    for await (const chunk of Deno.stdin.readable) {
        chunks += decoder.decode(chunk);
    }
    
    return chunks;
};
