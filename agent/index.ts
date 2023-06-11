import { OnLoadInterceptor } from "./lib/libOnLoadInterceptor";
import { log } from "./lib/libLogger";
import { hook_all_jni, hook_specific_jni } from "./lib/libJniInterceptor";


function hookNative(moduleName: string, function_offset: number){
    // OnLoadInterceptor(moduleName, base: NativePointer) => {
        
    // }
}

function main(){
    hookNative("", 0x0);
}

setImmediate(main);
