const char *const js_repl_qjs = "" \
  "import(\"os\").catch(console.error).then((os=>{!function(g){g.o"\
  "s=os;let running=!0;const Object=g.Object,String=g.String,Arr"\
  "ay=g.Array,Date=g.Date,Math=g.Math,isFinite=g.isFinite,parseF"\
  "loat=g.parseFloat,config_numcalc=!1,has_jscalc=\"function\"==ty"\
  "peof Fraction,has_bignum=\"function\"==typeof BigFloat,colors={"\
  "none:\"""\x1b""[0m\",black:\"""\x1b""[30m\",red:\"""\x1b""[31m\",green:\"""\x1b""[32"\
  "m\",yellow:\"""\x1b""[33m\",blue:\"""\x1b""[34m\",magenta:\"""\x1b""[35m\",cyan:"\
  "\"""\x1b""[36m\",white:\"""\x1b""[37m\",gray:\"""\x1b""[30;1m\",grey:\"""\x1b""[30;1"\
  "m\",bright_red:\"""\x1b""[31;1m\",bright_green:\"""\x1b""[32;1m\",bright_y"\
  "ellow:\"""\x1b""[33;1m\",bright_blue:\"""\x1b""[34;1m\",bright_magenta:\"""\x1b"""\
  "[35;1m\",bright_cyan:\"""\x1b""[36;1m\",bright_white:\"""\x1b""[37;1m\"};l"\
  "et styles;styles=config_numcalc?{default:\"black\",comment:\"whi"\
  "te\",string:\"green\",regex:\"cyan\",number:\"green\",keyword:\"blue\""\
  ",function:\"gray\",type:\"magenta\",identifier:\"yellow\",error:\"br"\
  "ight_red\",result:\"black\",error_msg:\"bright_red\"}:{default:\"wh"\
  "ite\",comment:\"white\",string:\"cyan\",regex:\"cyan\",number:\"green"\
  "\",keyword:\"magenta\",function:\"yellow\",type:\"magenta\",identifi"\
  "er:\"green\",error:\"red\",result:\"bright_white\",error_msg:\"brigh"\
  "t_red\"};const history=[];let clip_board=\"\",prec,expBits,log2_"\
  "10,pstate=\"\",prompt=\"\",plen=0,ps1;ps1=config_numcalc?\"> \":\"qj"\
  "s> \";const ps2=\" ... \",utf8=!0;let show_time=!1,show_colors=!"\
  "0,eval_time=0,mexpr=\"\",level=0,cmd=\"\",cursor_pos=0,last_cmd=\""\
  "\",last_cursor_pos=0,history_index,this_fun,last_fun,quote_fla"\
  "g=!1,utf8_state=0,utf8_val=0,term_fd,term_read_buf,term_width"\
  ",term_cursor_x=0;function termInit(){for(term_fd=0,(term_widt"\
  "h=+r2cmd(\"?vi $c\"))<1&&(term_width=80),term_read_buf=new Uint"\
  "8Array(64),cmd_start(),running=!0;running;)try{term_read_hand"\
  "ler(),flush()}catch(r){console.error(r)}}function term_read_h"\
  "andler(){var r=os.read(term_fd,term_read_buf.buffer,0,term_re"\
  "ad_buf.length);for(let e=0;e<r;e++)handle_byte(term_read_buf["\
  "e])}function handle_byte(r){utf8?0!==utf8_state&&128<=r&&r<19"\
  "2?(utf8_val=utf8_val<<6|63&r,0==--utf8_state&&handle_char(utf"\
  "8_val)):192<=r&&r<248?(utf8_state=1+(224<=r)+(240<=r),utf8_va"\
  "l=r&(1<<6-utf8_state)-1):(utf8_state=0,handle_char(r)):handle"\
  "_char(r)}function is_alpha(r){return\"string\"==typeof r&&(\"A\"<"\
  "=r&&r<=\"Z\"||\"a\"<=r&&r<=\"z\")}function is_digit(r){return\"strin"\
  "g\"==typeof r&&\"0\"<=r&&r<=\"9\"}function is_word(r){return\"strin"\
  "g\"==typeof r&&(is_alpha(r)||is_digit(r)||\"_\"===r||\"$\"===r)}fu"\
  "nction ucs_length(r){let e,t,n;var o=r.length;for(e=0,n=0;n<o"\
  ";n++)((t=r.charCodeAt(n))<56320||57344<=t)&&e++;return e}func"\
  "tion is_trailing_surrogate(r){if(\"string\"==typeof r)return 56"\
  "320<=(r=r.codePointAt(0))&&r<57344}function is_balanced(r,e){"\
  "switch(r+e){case\"()\":case\"[]\":case\"{}\":return 1}}function pri"\
  "nt_color_text(r,e,t){let n,o;for(o=e;o<r.length;){const e=t[n"\
  "=o];for(;++o<r.length&&t[o]===e;);write(colors[styles[e]||\"de"\
  "fault\"]),write(r.substring(n,o)),write(colors.none)}}function"\
  " print_csi(r,e){write(\"""\x1b""[\"+(1!==r?r:\"\")+e)}function move_c"\
  "ursor(r){let e;if(0<r)for(;0<r;)term_cursor_x===term_width-1?"\
  "(write(\"\\n\"),term_cursor_x=0,r--):(print_csi(e=Math.min(term_"\
  "width-1-term_cursor_x,r),\"C\"),r-=e,term_cursor_x+=e);else for"\
  "(r=-r;0<r;)0===term_cursor_x?(print_csi(1,\"A\"),print_csi(term"\
  "_width-1,\"C\"),r--,term_cursor_x=term_width-1):(print_csi(e=Ma"\
  "th.min(r,term_cursor_x),\"D\"),r-=e,term_cursor_x-=e)}function "\
  "update(){var r;cmd!==last_cmd&&(show_colors||last_cmd.substri"\
  "ng(0,last_cursor_pos)!==cmd.substring(0,last_cursor_pos)?(mov"\
  "e_cursor(-ucs_length(last_cmd.substring(0,last_cursor_pos))),"\
  "show_colors?print_color_text(r=mexpr?mexpr+\"\\n\"+cmd:cmd,r.len"\
  "gth-cmd.length,colorize_js(r)[2]):write(cmd)):write(cmd.subst"\
  "ring(last_cursor_pos)),0==(term_cursor_x=(term_cursor_x+ucs_l"\
  "ength(cmd))%term_width)&&write(\" \\b\"),write(\"""\x1b""[J\"),last_cm"\
  "d=cmd,last_cursor_pos=cmd.length),cursor_pos>last_cursor_pos?"\
  "move_cursor(ucs_length(cmd.substring(last_cursor_pos,cursor_p"\
  "os))):cursor_pos<last_cursor_pos&&move_cursor(-ucs_length(cmd"\
  ".substring(cursor_pos,last_cursor_pos))),last_cursor_pos=curs"\
  "or_pos,flush()}function insert(r){r&&(cmd=cmd.substring(0,cur"\
  "sor_pos)+r+cmd.substring(cursor_pos),cursor_pos+=r.length)}fu"\
  "nction quoted_insert(){quote_flag=!0}function abort(){return "\
  "cmd=\"\",cursor_pos=0,-2}function alert(){}function beginning_o"\
  "f_line(){cursor_pos=0}function end_of_line(){cursor_pos=cmd.l"\
  "ength}function forward_char(){if(cursor_pos<cmd.length)for(cu"\
  "rsor_pos++;is_trailing_surrogate(cmd.charAt(cursor_pos));)cur"\
  "sor_pos++}function backward_char(){if(0<cursor_pos)for(cursor"\
  "_pos--;is_trailing_surrogate(cmd.charAt(cursor_pos));)cursor_"\
  "pos--}function skip_word_forward(r){for(;r<cmd.length&&!is_wo"\
  "rd(cmd.charAt(r));)r++;for(;r<cmd.length&&is_word(cmd.charAt("\
  "r));)r++;return r}function skip_word_backward(r){for(;0<r&&!i"\
  "s_word(cmd.charAt(r-1));)r--;for(;0<r&&is_word(cmd.charAt(r-1"\
  "));)r--;return r}function forward_word(){cursor_pos=skip_word"\
  "_forward(cursor_pos)}function backward_word(){cursor_pos=skip"\
  "_word_backward(cursor_pos)}function accept_line(){return writ"\
  "e(\"\\n\"),history_add(cmd),-1}function history_add(r){r&&histor"\
  "y.push(r),history_index=history.length}function previous_hist"\
  "ory(){0<history_index&&(history_index===history.length&&histo"\
  "ry.push(cmd),history_index--,cmd=history[history_index],curso"\
  "r_pos=cmd.length)}function next_history(){history_index<histo"\
  "ry.length-1&&(history_index++,cmd=history[history_index],curs"\
  "or_pos=cmd.length)}function history_search(r){var e=cursor_po"\
  "s;for(let n=1;n<=history.length;n++){var t=(history.length+n*"\
  "r+history_index)%history.length;if(history[t].substring(0,e)="\
  "==cmd.substring(0,e))return history_index=t,void(cmd=history["\
  "t])}}function history_search_backward(){return history_search"\
  "(-1)}function history_search_forward(){return history_search("\
  "1)}function delete_char_dir(r){let e,t;if(e=cursor_pos,r<0)fo"\
  "r(e--;is_trailing_surrogate(cmd.charAt(e));)e--;for(t=e+1;is_"\
  "trailing_surrogate(cmd.charAt(t));)t++;0<=e&&e<cmd.length&&(l"\
  "ast_fun===kill_region?kill_region(e,t,r):(cmd=cmd.substring(0"\
  ",e)+cmd.substring(t),cursor_pos=e))}function delete_char(){de"\
  "lete_char_dir(1)}function control_d(){if(0===cmd.length)retur"\
  "n write(\"\\n\"),running=!1,-3;delete_char_dir(1)}function backw"\
  "ard_delete_char(){delete_char_dir(-1)}function transpose_char"\
  "s(){let r=cursor_pos;1<cmd.length&&0<r&&(r===cmd.length&&r--,"\
  "cmd=cmd.substring(0,r-1)+cmd.substring(r,r+1)+cmd.substring(r"\
  "-1,r)+cmd.substring(r+1),cursor_pos=r+1)}function transpose_w"\
  "ords(){var r=skip_word_backward(cursor_pos),e=skip_word_forwa"\
  "rd(r),t=skip_word_forward(cursor_pos),n=skip_word_backward(t)"\
  ";r<e&&e<=cursor_pos&&cursor_pos<=n&&n<t&&(cmd=cmd.substring(0"\
  ",r)+cmd.substring(n,t)+cmd.substring(e,n)+cmd.substring(r,e),"\
  "cursor_pos=t)}function upcase_word(){var r=skip_word_forward("\
  "cursor_pos);cmd=cmd.substring(0,cursor_pos)+cmd.substring(cur"\
  "sor_pos,r).toUpperCase()+cmd.substring(r)}function downcase_w"\
  "ord(){var r=skip_word_forward(cursor_pos);cmd=cmd.substring(0"\
  ",cursor_pos)+cmd.substring(cursor_pos,r).toLowerCase()+cmd.su"\
  "bstring(r)}function kill_region(r,e,t){var n=cmd.substring(r,"\
  "e);last_fun!==kill_region?clip_board=n:t<0?clip_board=n+clip_"\
  "board:clip_board+=n,cmd=cmd.substring(0,r)+cmd.substring(e),c"\
  "ursor_pos>e?cursor_pos-=e-r:cursor_pos>r&&(cursor_pos=r),this"\
  "_fun=kill_region}function kill_line(){kill_region(cursor_pos,"\
  "cmd.length,1)}function backward_kill_line(){kill_region(0,cur"\
  "sor_pos,-1)}function kill_word(){kill_region(cursor_pos,skip_"\
  "word_forward(cursor_pos),1)}function backward_kill_word(){kil"\
  "l_region(skip_word_backward(cursor_pos),cursor_pos,-1)}functi"\
  "on yank(){insert(clip_board)}function control_c(){console.log"\
  "(\"^C\"),reset(),readline_print_prompt()}function reset(){cmd=\""\
  "\",cursor_pos=0}function get_context_word(r,e){let t=\"\";for(;0"\
  "<e&&is_word(r[e-1]);)t=r[--e]+t;return t}function get_context"\
  "_object(line,pos){let obj,base,c;if(pos<=0||0<=\" ~!%^&*(-+={["\
  "|:;,<>?/\".indexOf(line[pos-1]))return g;if(2<=pos&&\".\"===line"\
  "[pos-1])switch(pos--,obj={},c=line[pos-1]){case\"'\":case'\"':re"\
  "turn\"a\";case\"]\":return[];case\"}\":return{};case\"/\":return/ /;d"\
  "efault:return is_word(c)?(base=get_context_word(line,pos),[\"t"\
  "rue\",\"false\",\"null\",\"this\"].includes(base)||!isNaN(+base)?eva"\
  "l(base):(obj=get_context_object(line,pos-base.length),null==o"\
  "bj?obj:obj===g&&void 0===obj[base]?eval(base):obj[base])):{}}"\
  "}function get_completions(r,e){let t,n,o;var i=get_context_wo"\
  "rd(r,e),s=[];for(n=0,t=r=get_context_object(r,e-i.length);n<1"\
  "0&&null!=t;n++){const r=Object.getOwnPropertyNames(t);for(o=0"\
  ";o<r.length;o++){const e=r[o];\"string\"==typeof e&&\"\"+ +e!==e&"\
  "&e.startsWith(i)&&s.push(e)}t=Object.getPrototypeOf(t)}if(1<s"\
  ".length){for(s.sort((function(r,e){if(r[0]!==e[0]){if(\"_\"===r"\
  "[0])return 1;if(\"_\"===e[0])return-1}return r<e?-1:e<r?1:0})),"\
  "n=o=1;n<s.length;n++)s[n]!==s[n-1]&&(s[o++]=s[n]);s.length=o}"\
  "return{tab:s,pos:i.length,ctx:r}}function completion(){let r,"\
  "e,t,n,o,i,s,c,a,l;var _=get_completions(cmd,cursor_pos),u=_.t"\
  "ab;if(0!==u.length){for(r=u[0],n=r.length,e=1;e<u.length;e++)"\
  "for(o=u[e],t=0;t<n;t++)if(o[t]!==r[t]){n=t;break}for(e=_.pos;"\
  "e<n;e++)insert(r[e]);if(last_fun===completion&&1===u.length){"\
  "const r=_.ctx[u[0]];\"function\"==typeof r?(insert(\"(\"),0===r.l"\
  "ength&&insert(\")\")):\"object\"==typeof r&&insert(\".\")}if(last_f"\
  "un===completion&&2<=u.length){for(i=0,e=0;e<u.length;e++)i=Ma"\
  "th.max(i,u[e].length);for(i+=2,c=Math.max(1,Math.floor((term_"\
  "width+1)/i)),l=Math.ceil(u.length/c),write(\"\\n\"),a=0;a<l;a++)"\
  "{for(s=0;s<c&&!((e=s*l+a)>=u.length);s++)r=u[e],s!==c-1&&(r=r"\
  ".padEnd(i)),write(r);write(\"\\n\")}readline_print_prompt()}}}co"\
  "nst commands={\"""\x01""\":beginning_of_line,\"""\x02""\":backward_char,\""\
  """\x03""\":control_c,\"""\x04""\":control_d,\"""\x05""\":end_of_line,\"""\x06""\":fo"\
  "rward_char,\"""\x07""\":abort,\"\\b\":backward_delete_char,\"\\t\":comple"\
  "tion,\"\\n\":accept_line,\"\\v\":kill_line,\"\\r\":accept_line,\"""\x0e""\":"\
  "next_history,\"""\x10""\":previous_history,\"""\x11""\":quoted_insert,\"""\x12"""\
  "\":alert,\"""\x13""\":alert,\"""\x14""\":transpose_chars,\"""\x17""\":backward_k"\
  "ill_word,\"""\x18""\":reset,\"""\x19""\":yank,\"""\x1b""OA\":previous_history,\""\
  """\x1b""OB\":next_history,\"""\x1b""OC\":forward_char,\"""\x1b""OD\":backward_"\
  "char,\"""\x1b""OF\":forward_word,\"""\x1b""OH\":backward_word,\"""\x1b""[1;5C\""\
  ":forward_word,\"""\x1b""[1;5D\":backward_word,\"""\x1b""[1~\":beginning_o"\
  "f_line,\"""\x1b""[3~\":delete_char,\"""\x1b""[4~\":end_of_line,\"""\x1b""[5~\":"\
  "history_search_backward,\"""\x1b""[6~\":history_search_forward,\"""\x1b"""\
  "[A\":previous_history,\"""\x1b""[B\":next_history,\"""\x1b""[C\":forward_c"\
  "har,\"""\x1b""[D\":backward_char,\"""\x1b""[F\":end_of_line,\"""\x1b""[H\":begi"\
  "nning_of_line,\"""\x1b""""\x7f""\":backward_kill_word,\"""\x1b""b\":backward_"\
  "word,\"""\x1b""d\":kill_word,\"""\x1b""f\":forward_word,\"""\x1b""k\":backward_"\
  "kill_line,\"""\x1b""l\":downcase_word,\"""\x1b""t\":transpose_words,\"""\x1b"""\
  "u\":upcase_word,\"""\x7f""\":backward_delete_char};function dupstr(r"\
  ",e){let t=\"\";for(;0<e--;)t+=r;return t}let readline_keys,read"\
  "line_state,readline_cb;function readline_print_prompt(){write"\
  "(prompt),term_cursor_x=ucs_length(prompt)%term_width,last_cmd"\
  "=\"\",last_cursor_pos=0}function readline_start(r,e){if(cmd=r||"\
  "\"\",cursor_pos=cmd.length,history_index=history.length,readlin"\
  "e_cb=e,prompt=pstate,mexpr)prompt=(prompt+=dupstr(\" \",plen-pr"\
  "ompt.length))+ps2;else{if(show_time){let r=Math.round(eval_ti"\
  "me)+\" \";eval_time=0,r=dupstr(\"0\",5-r.length)+r,prompt+=r.subs"\
  "tring(0,r.length-4)+\".\"+r.substring(r.length-4)}plen=prompt.l"\
  "ength,show_colors&&(prompt+=colors.yellow),prompt+=ps1,show_c"\
  "olors&&(prompt+=colors.none)}readline_print_prompt(),update()"\
  ",readline_state=0}function handle_char(r){var e=String.fromCo"\
  "dePoint(r);switch(readline_state){case 0:\"""\x1b""\"===e?(readline"\
  "_keys=e,readline_state=1):handle_key(e);break;case 1:readline"\
  "_keys+=e,readline_state=\"[\"===e?2:\"O\"===e?3:(handle_key(readl"\
  "ine_keys),0);break;case 2:readline_keys+=e,\";\"===e||\"0\"<=e&&e"\
  "<=\"9\"||(handle_key(readline_keys),readline_state=0);break;cas"\
  "e 3:handle_key(readline_keys+=e),readline_state=0}}function h"\
  "andle_key(r){var e;if(quote_flag)1===ucs_length(r)&&insert(r)"\
  ",quote_flag=!1;else if(e=commands[r]){switch((this_fun=e)(r))"\
  "{case-1:return readline_cb(cmd);case-2:return readline_cb(nul"\
  "l);case-3:return}last_fun=this_fun}else 1===ucs_length(r)&&\" "\
  "\"<=r?(insert(r),last_fun=insert):alert();cursor_pos=cursor_po"\
  "s<0?0:cursor_pos>cmd.length?cmd.length:cursor_pos,update()}le"\
  "t hex_mode=!1,eval_mode=\"std\";function number_to_string(r,e){"\
  "if(isFinite(r)){let t;return 0===r?t=1/r<0?\"-0\":\"0\":16===e&&r"\
  "===Math.floor(r)?(t=r<0?(r=-r,\"-\"):\"\",t+=\"0x\"+r.toString(16))"\
  ":t=r.toString(),t}return r.toString()}function bigfloat_to_st"\
  "ring(r,e){let t;return BigFloat.isFinite(r)?(0===r?t=1/r<0?\"-"\
  "0\":\"0\":16===e?(t=r<0?(r=-r,\"-\"):\"\",t+=\"0x\"+r.toString(16)):t="\
  "r.toString(),\"bigfloat\"==typeof r&&\"math\"!==eval_mode?t+=\"l\":"\
  "\"std\"!==eval_mode&&t.indexOf(\".\")<0&&(16===e&&t.indexOf(\"p\")<"\
  "0||10===e&&t.indexOf(\"e\")<0)&&(t+=\".0\"),t):\"math\"!==eval_mode"\
  "?\"BigFloat(\"+r.toString()+\")\":r.toString()}function bigint_to"\
  "_string(r,e){let t;return 16===e?(t=r<0?(r=-r,\"-\"):\"\",t+=\"0x\""\
  "+r.toString(16)):t=r.toString(),\"std\"===eval_mode&&(t+=\"n\"),t"\
  "}function print(r){const e=[];!function r(t){let n,o,i,s,c;va"\
  "r a=typeof t;if(\"object\"==a)if(null===t)write(t);else if(0<=e"\
  ".indexOf(t))write(\"[circular]\");else if(has_jscalc&&(t instan"\
  "ceof Fraction||t instanceof Complex||t instanceof Mod||t inst"\
  "anceof Polynomial||t instanceof PolyMod||t instanceof Rationa"\
  "lFunction||t instanceof Series))write(t.toString());else{if(e"\
  ".push(t),Array.isArray(t)){for(n=t.length,write(\"[ \"),o=0;o<n"\
  ";o++)if(0!==o&&write(\", \"),o in t?r(t[o]):write(\"<empty>\"),20"\
  "<o){write(\"...\");break}write(\" ]\")}else if(\"RegExp\"===Object."\
  "__getClass(t))write(t.toString());else{for(i=Object.keys(t),n"\
  "=i.length,write(\"{ \"),o=0;o<n;o++)0!==o&&write(\", \"),s=i[o],w"\
  "rite(s,\": \"),r(t[s]);write(\" }\")}e.pop(t)}else\"string\"==a?(79"\
  "<(c=t.__quote()).length&&(c=c.substring(0,75)+'...\"'),write(c"\
  ")):\"number\"==a?write(number_to_string(t,hex_mode?16:10)):\"big"\
  "int\"==a?write(bigint_to_string(t,hex_mode?16:10)):\"bigfloat\"="\
  "=a?write(bigfloat_to_string(t,hex_mode?16:10)):\"bigdecimal\"=="\
  "a?write(t.toString()+\"m\"):\"symbol\"==a?write(String(t)):\"funct"\
  "ion\"==a?write(\"function \"+t.name+\"()\"):write(t)}(r)}function "\
  "extract_directive(r){let e;if(\"\\\\\"!==r[0])return\"\";for(e=1;e<"\
  "r.length&&is_alpha(r[e]);e++);return r.substring(1,e)}functio"\
  "n handle_directive(r,e){let t,n,o;if(\"h\"===r||\"?\"===r||\"help\""\
  "===r)help();else{if(\"load\"===r){let t=e.substring(r.length+1)"\
  ".trim();return t.lastIndexOf(\".\")<=t.lastIndexOf(\"/\")&&(t+=\"."\
  "js\"),0}if(\"x\"===r)hex_mode=!0;else if(\"d\"===r)hex_mode=!1;els"\
  "e if(\"t\"===r)show_time=!show_time;else{if(has_bignum&&\"p\"===r"\
  "){if(1===(t=e.substring(r.length+1).trim().split(\" \")).length"\
  "&&\"\"===t[0])write(\"BigFloat precision=\"+prec+\" bits (~\"+Math."\
  "floor(prec/log2_10)+\" digits), exponent size=\"+expBits+\" bits"\
  "\\n\");else if(\"f16\"===t[0])prec=11,expBits=5;else if(\"f32\"===t"\
  "[0])prec=24,expBits=8;else if(\"f64\"===t[0])prec=53,expBits=11"\
  ";else if(\"f128\"===t[0])prec=113,expBits=15;else{if(n=parseInt"\
  "(t[0]),o=2<=t.length?parseInt(t[1]):BigFloatEnv.expBitsMax,Nu"\
  "mber.isNaN(n)||n<BigFloatEnv.precMin||n>BigFloatEnv.precMax)r"\
  "eturn write(\"Invalid precision\\n\"),0;if(Number.isNaN(o)||o<Bi"\
  "gFloatEnv.expBitsMin||o>BigFloatEnv.expBitsMax)return write(\""\
  "Invalid exponent bits\\n\"),0;prec=n,expBits=o}return}if(has_bi"\
  "gnum&&\"digits\"===r)return t=e.substring(r.length+1).trim(),(n"\
  "=Math.ceil(parseFloat(t)*log2_10))<BigFloatEnv.precMin||n>Big"\
  "FloatEnv.precMax?write(\"Invalid precision\\n\"):(prec=n,expBits"\
  "=BigFloatEnv.expBitsMax),0;if(has_bignum&&\"mode\"===r)return\"\""\
  "===(t=e.substring(r.length+1).trim())?write(\"Running mode=\"+e"\
  "val_mode+\"\\n\"):\"std\"===t||\"math\"===t?eval_mode=t:write(\"Inval"\
  "id mode\\n\"),0;if(\"clear\"===r)write(\"""\x1b""[H""\x1b""[J\");else if(\"c"\
  "\"===r)show_colors=!show_colors;else{if(\"q\"===r)return running"\
  "=!1,1;if(has_jscalc&&\"a\"===r)algebraicMode=!0;else{if(!has_js"\
  "calc||\"n\"!==r)return write(\"Unknown directive: \"+r+\"\\n\"),0;al"\
  "gebraicMode=!1}}}}return 1}function help(){function r(r){retu"\
  "rn r?\"*\":\" \"}write(\"\\\\h          this help\\n\\\\x         \"+r(h"\
  "ex_mode)+\"hexadecimal number display\\n\\\\c          toggle col"\
  "ors\\n\\\\d         \"+r(!hex_mode)+\"decimal number display\\n\\\\cl"\
  "ear      clear the terminal\\n\"),has_jscalc&&write(\"\\\\a       "\
  "  \"+r(algebraicMode)+\"algebraic mode\\n\\\\n         \"+r(!algebr"\
  "aicMode)+\"numeric mode\\n\"),has_bignum&&(write(\"\\\\p [m [e]]  s"\
  "et the BigFloat precision to 'm' bits\\n\\\\digits n   set the B"\
  "igFloat precision to 'ceil(n*log2(10))' bits\\n\"),has_jscalc||"\
  "write(\"\\\\mode [std|math] change the running mode (current = \""\
  "+eval_mode+\")\\n\")),config_numcalc||write(\"\\\\q          exit\\n"\
  "\")}function eval_and_print(expr){let result;try{\"math\"===eval"\
  "_mode&&(expr='\"use math\"; void 0;'+expr);const now=(new Date)"\
  ".getTime();result=eval(expr),eval_time=(new Date).getTime()-n"\
  "ow,write(colors[styles.result]),print(result),write(\"\\n\"),wri"\
  "te(colors.none),g._=result}catch(r){show_colors&&write(colors"\
  "[styles.error_msg]),r instanceof Error?r.stack&&write(r.stack"\
  "):write(\"Throw: \"),show_colors&&write(colors.none)}}function "\
  "cmd_start(){var r;config_numcalc||(r=has_jscalc?\"QJSCalc\":\"Qu"\
  "ickJS\",console.log(r,'- Type \"\\\\h\" for help')),has_bignum&&(l"\
  "og2_10=Math.log(10)/Math.log(2),prec=113,expBits=15,has_jscal"\
  "c)&&(eval_mode=\"math\",g.algebraicMode=config_numcalc),cmd_rea"\
  "dline_start()}function cmd_readline_start(){try{readline_star"\
  "t(dupstr(\"    \",level),readline_handle_cmd)}catch(r){console."\
  "error(\"ERROR\",r)}}function readline_handle_cmd(r){handle_cmd("\
  "r),cmd_readline_start()}function handle_cmd(r){if(null===r)re"\
  "turn\"\";if(\"?\"===r||\"h\"===r)return help();var e=extract_direct"\
  "ive(r);if(0<e.length){if(!handle_directive(e,r))return;r=r.su"\
  "bstring(e.length+1)}\"\"!==r&&(e=colorize_js(r=mexpr?mexpr+\"\\n\""\
  "+r:r),pstate=e[0],level=e[1],pstate?mexpr=r:(mexpr=\"\",has_big"\
  "num?BigFloatEnv.setPrec(eval_and_print.bind(null,r),prec,expB"\
  "its):eval_and_print(r),level=0))}function colorize_js(r){let "\
  "e,t,n;const o=r.length;let i,s=\"\",c=0,a=1;const l=[];function"\
  " _(r){s+=r}function u(){return s.substring(s.length-1)}functi"\
  "on d(){var r=u();return s=s.substring(0,s.length-1),r}functio"\
  "n f(r,e){for(;l.length<r;)l.push(\"default\");for(;l.length<e;)"\
  "l.push(i)}for(e=0;e<o;){switch(i=null,n=e,t=r[e++]){case\" \":c"\
  "ase\"\\t\":case\"\\r\":case\"\\n\":continue;case\"+\":case\"-\":if(e<o&&r["\
  "e]===t){e++;continue}a=1;continue;case\"/\":if(e<o&&\"*\"===r[e])"\
  "{for(i=\"comment\",_(\"/\"),e++;e<o-1;e++)if(\"*\"===r[e]&&\"/\"===r["\
  "e+1]){e+=2,d();break}break}if(e<o&&\"/\"===r[e]){for(i=\"comment"\
  "\",e++;e<o&&\"\\n\"!==r[e];e++);break}if(a){for(i=\"regex\",_(\"/\");"\
  "e<o;)if(\"\\n\"!==(t=r[e++]))if(\"\\\\\"!==t)if(\"[\"!==u())if(\"[\"!==t"\
  "){if(\"/\"===t){for(d();e<o&&is_word(r[e]);)e++;break}}else _(\""\
  "[\"),\"[\"!==r[e]&&\"]\"!==r[e]||e++;else\"]\"===t&&d();else e<o&&e+"\
  "+;else i=\"error\";a=0;break}a=1;continue;case\"'\":case'\"':case\""\
  "`\":(function(n){for(i=\"string\",_(n);e<o;)if(\"\\n\"!==(t=r[e++])"\
  "){if(\"\\\\\"===t){if(e>=o)break;e++}else if(t===n){d();break}}el"\
  "se i=\"error\"})(t),a=0;break;case\"(\":case\"[\":case\"{\":a=1,c++,_"\
  "(t);continue;case\")\":case\"]\":case\"}\":if((a=0)<c&&is_balanced("\
  "u(),t)){c--,d();continue}i=\"error\";break;default:if(is_digit("\
  "t)){for(i=\"number\";e<o&&(is_word(r[e])||\".\"===r[e]&&(e===o-1|"\
  "|\".\"!==r[e+1]));)e++;a=0}else{if(!is_word(t)&&\"$\"!==t){a=1;co"\
  "ntinue}!function(){for(a=1;e<o&&is_word(r[e]);)e++;var t=\"|\"+"\
  "r.substring(n,e)+\"|\";if(0<=\"|break|case|catch|continue|debugg"\
  "er|default|delete|do|else|finally|for|function|if|in|instance"\
  "of|new|return|switch|this|throw|try|typeof|while|with|class|c"\
  "onst|enum|import|export|extends|super|implements|interface|le"\
  "t|package|private|protected|public|static|yield|undefined|nul"\
  "l|true|false|Infinity|NaN|eval|arguments|await|\".indexOf(t))r"\
  "eturn i=\"keyword\",0<=\"|this|super|undefined|null|true|false|I"\
  "nfinity|NaN|arguments|\".indexOf(t)&&(a=0);let s=e;for(;s<o&&\""\
  " \"===r[s];)s++;s<o&&\"(\"===r[s]?i=\"function\":0<=\"|void|var|\".i"\
  "ndexOf(t)?i=\"type\":(i=\"identifier\",a=0)}()}}i&&f(n,e)}return "\
  "f(o,o),[s,c,l]}config_numcalc&&(g.execCmd=function(r){switch("\
  "r){case\"dec\":hex_mode=!1;break;case\"hex\":hex_mode=!0;break;ca"\
  "se\"num\":algebraicMode=!1;break;case\"alg\":algebraicMode=!0}});"\
  "try{termInit()}catch(r){console.error(r)}}(globalThis)}));\n";
