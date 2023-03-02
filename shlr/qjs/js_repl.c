static const char *const js_repl_qjs = "" \
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
  "ler(),flush()}catch(e){console.error(e)}}function term_read_h"\
  "andler(){var e=os.read(term_fd,term_read_buf.buffer,0,term_re"\
  "ad_buf.length);for(let r=0;r<e;r++)handle_byte(term_read_buf["\
  "r])}function handle_byte(e){utf8?0!==utf8_state&&128<=e&&e<19"\
  "2?(utf8_val=utf8_val<<6|63&e,0==--utf8_state&&handle_char(utf"\
  "8_val)):192<=e&&e<248?(utf8_state=1+(224<=e)+(240<=e),utf8_va"\
  "l=e&(1<<6-utf8_state)-1):(utf8_state=0,handle_char(e)):handle"\
  "_char(e)}function is_alpha(e){return\"string\"==typeof e&&(\"A\"<"\
  "=e&&e<=\"Z\"||\"a\"<=e&&e<=\"z\")}function is_digit(e){return\"strin"\
  "g\"==typeof e&&\"0\"<=e&&e<=\"9\"}function is_word(e){return\"strin"\
  "g\"==typeof e&&(is_alpha(e)||is_digit(e)||\"_\"===e||\"$\"===e)}fu"\
  "nction ucs_length(e){let r,t,n;var o=e.length;for(r=0,n=0;n<o"\
  ";n++)((t=e.charCodeAt(n))<56320||57344<=t)&&r++;return r}func"\
  "tion is_trailing_surrogate(e){if(\"string\"==typeof e)return 56"\
  "320<=(e=e.codePointAt(0))&&e<57344}function is_balanced(e,r){"\
  "switch(e+r){case\"()\":case\"[]\":case\"{}\":return 1}}function pri"\
  "nt_color_text(e,r,t){let n,o;for(o=r;o<e.length;){const r=t[n"\
  "=o];for(;++o<e.length&&t[o]===r;);write(colors[styles[r]||\"de"\
  "fault\"]),write(e.substring(n,o)),write(colors.none)}}function"\
  " print_csi(e,r){write(\"""\x1b""[\"+(1!==e?e:\"\")+r)}function move_c"\
  "ursor(e){let r;if(0<e)for(;0<e;)term_cursor_x===term_width-1?"\
  "(write(\"\\n\"),term_cursor_x=0,e--):(print_csi(r=Math.min(term_"\
  "width-1-term_cursor_x,e),\"C\"),e-=r,term_cursor_x+=r);else for"\
  "(e=-e;0<e;)0===term_cursor_x?(print_csi(1,\"A\"),print_csi(term"\
  "_width-1,\"C\"),e--,term_cursor_x=term_width-1):(print_csi(r=Ma"\
  "th.min(e,term_cursor_x),\"D\"),e-=r,term_cursor_x-=r)}function "\
  "update(){var e;cmd!==last_cmd&&(show_colors||last_cmd.substri"\
  "ng(0,last_cursor_pos)!==cmd.substring(0,last_cursor_pos)?(mov"\
  "e_cursor(-ucs_length(last_cmd.substring(0,last_cursor_pos))),"\
  "show_colors?print_color_text(e=mexpr?mexpr+\"\\n\"+cmd:cmd,e.len"\
  "gth-cmd.length,colorize_js(e)[2]):write(cmd)):write(cmd.subst"\
  "ring(last_cursor_pos)),0==(term_cursor_x=(term_cursor_x+ucs_l"\
  "ength(cmd))%term_width)&&write(\" \\b\"),write(\"""\x1b""[J\"),last_cm"\
  "d=cmd,last_cursor_pos=cmd.length),cursor_pos>last_cursor_pos?"\
  "move_cursor(ucs_length(cmd.substring(last_cursor_pos,cursor_p"\
  "os))):cursor_pos<last_cursor_pos&&move_cursor(-ucs_length(cmd"\
  ".substring(cursor_pos,last_cursor_pos))),last_cursor_pos=curs"\
  "or_pos,flush()}function insert(e){e&&(cmd=cmd.substring(0,cur"\
  "sor_pos)+e+cmd.substring(cursor_pos),cursor_pos+=e.length)}fu"\
  "nction quoted_insert(){quote_flag=!0}function abort(){return "\
  "cmd=\"\",cursor_pos=0,-2}function alert(){}function beginning_o"\
  "f_line(){cursor_pos=0}function end_of_line(){cursor_pos=cmd.l"\
  "ength}function forward_char(){if(cursor_pos<cmd.length)for(cu"\
  "rsor_pos++;is_trailing_surrogate(cmd.charAt(cursor_pos));)cur"\
  "sor_pos++}function backward_char(){if(0<cursor_pos)for(cursor"\
  "_pos--;is_trailing_surrogate(cmd.charAt(cursor_pos));)cursor_"\
  "pos--}function skip_word_forward(e){for(;e<cmd.length&&!is_wo"\
  "rd(cmd.charAt(e));)e++;for(;e<cmd.length&&is_word(cmd.charAt("\
  "e));)e++;return e}function skip_word_backward(e){for(;0<e&&!i"\
  "s_word(cmd.charAt(e-1));)e--;for(;0<e&&is_word(cmd.charAt(e-1"\
  "));)e--;return e}function forward_word(){cursor_pos=skip_word"\
  "_forward(cursor_pos)}function backward_word(){cursor_pos=skip"\
  "_word_backward(cursor_pos)}function accept_line(){return writ"\
  "e(\"\\n\"),history_add(cmd),-1}function history_add(e){e&&histor"\
  "y.push(e),history_index=history.length}function previous_hist"\
  "ory(){0<history_index&&(history_index===history.length&&histo"\
  "ry.push(cmd),history_index--,cmd=history[history_index],curso"\
  "r_pos=cmd.length)}function next_history(){history_index<histo"\
  "ry.length-1&&(history_index++,cmd=history[history_index],curs"\
  "or_pos=cmd.length)}function history_search(e){var r=cursor_po"\
  "s;for(let n=1;n<=history.length;n++){var t=(history.length+n*"\
  "e+history_index)%history.length;if(history[t].substring(0,r)="\
  "==cmd.substring(0,r))return history_index=t,void(cmd=history["\
  "t])}}function history_search_backward(){return history_search"\
  "(-1)}function history_search_forward(){return history_search("\
  "1)}function delete_char_dir(e){let r,t;if(r=cursor_pos,e<0)fo"\
  "r(r--;is_trailing_surrogate(cmd.charAt(r));)r--;for(t=r+1;is_"\
  "trailing_surrogate(cmd.charAt(t));)t++;0<=r&&r<cmd.length&&(l"\
  "ast_fun===kill_region?kill_region(r,t,e):(cmd=cmd.substring(0"\
  ",r)+cmd.substring(t),cursor_pos=r))}function delete_char(){de"\
  "lete_char_dir(1)}function control_d(){if(0===cmd.length)retur"\
  "n write(\"\\n\"),running=!1,-3;delete_char_dir(1)}function backw"\
  "ard_delete_char(){delete_char_dir(-1)}function transpose_char"\
  "s(){let e=cursor_pos;1<cmd.length&&0<e&&(e===cmd.length&&e--,"\
  "cmd=cmd.substring(0,e-1)+cmd.substring(e,e+1)+cmd.substring(e"\
  "-1,e)+cmd.substring(e+1),cursor_pos=e+1)}function transpose_w"\
  "ords(){var e=skip_word_backward(cursor_pos),r=skip_word_forwa"\
  "rd(e),t=skip_word_forward(cursor_pos),n=skip_word_backward(t)"\
  ";e<r&&r<=cursor_pos&&cursor_pos<=n&&n<t&&(cmd=cmd.substring(0"\
  ",e)+cmd.substring(n,t)+cmd.substring(r,n)+cmd.substring(e,r),"\
  "cursor_pos=t)}function upcase_word(){var e=skip_word_forward("\
  "cursor_pos);cmd=cmd.substring(0,cursor_pos)+cmd.substring(cur"\
  "sor_pos,e).toUpperCase()+cmd.substring(e)}function downcase_w"\
  "ord(){var e=skip_word_forward(cursor_pos);cmd=cmd.substring(0"\
  ",cursor_pos)+cmd.substring(cursor_pos,e).toLowerCase()+cmd.su"\
  "bstring(e)}function kill_region(e,r,t){var n=cmd.substring(e,"\
  "r);last_fun!==kill_region?clip_board=n:t<0?clip_board=n+clip_"\
  "board:clip_board+=n,cmd=cmd.substring(0,e)+cmd.substring(r),c"\
  "ursor_pos>r?cursor_pos-=r-e:cursor_pos>e&&(cursor_pos=e),this"\
  "_fun=kill_region}function kill_line(){kill_region(cursor_pos,"\
  "cmd.length,1)}function backward_kill_line(){kill_region(0,cur"\
  "sor_pos,-1)}function kill_word(){kill_region(cursor_pos,skip_"\
  "word_forward(cursor_pos),1)}function backward_kill_word(){kil"\
  "l_region(skip_word_backward(cursor_pos),cursor_pos,-1)}functi"\
  "on yank(){insert(clip_board)}function control_c(){console.log"\
  "(\"^C\"),reset(),readline_print_prompt()}function reset(){cmd=\""\
  "\",cursor_pos=0}function get_context_word(e,r){let t=\"\";for(;0"\
  "<r&&is_word(e[r-1]);)t=e[--r]+t;return t}function get_context"\
  "_object(line,pos){let obj,base,c;if(pos<=0||0<=\" ~!%^&*(-+={["\
  "|:;,<>?/\".indexOf(line[pos-1]))return g;if(2<=pos&&\".\"===line"\
  "[pos-1])switch(pos--,obj={},c=line[pos-1]){case\"'\":case'\"':re"\
  "turn\"a\";case\"]\":return[];case\"}\":return{};case\"/\":return/ /;d"\
  "efault:return is_word(c)?(base=get_context_word(line,pos),[\"t"\
  "rue\",\"false\",\"null\",\"this\"].includes(base)||!isNaN(+base)?eva"\
  "l(base):(obj=get_context_object(line,pos-base.length),null==o"\
  "bj?obj:obj===g&&void 0===obj[base]?eval(base):obj[base])):{}}"\
  "}function get_completions(e,r){let t,n,o;var i=get_context_wo"\
  "rd(e,r),s=[];for(n=0,t=e=get_context_object(e,r-i.length);n<1"\
  "0&&null!=t;n++){const e=Object.getOwnPropertyNames(t);for(o=0"\
  ";o<e.length;o++){const r=e[o];\"string\"==typeof r&&\"\"+ +r!==r&"\
  "&r.startsWith(i)&&s.push(r)}t=Object.getPrototypeOf(t)}if(1<s"\
  ".length){for(s.sort((function(e,r){if(e[0]!==r[0]){if(\"_\"===e"\
  "[0])return 1;if(\"_\"===r[0])return-1}return e<r?-1:r<e?1:0})),"\
  "n=o=1;n<s.length;n++)s[n]!==s[n-1]&&(s[o++]=s[n]);s.length=o}"\
  "return{tab:s,pos:i.length,ctx:e}}function completion(){let e,"\
  "r,t,n,o,i,s,c,a,l;var _=get_completions(cmd,cursor_pos),u=_.t"\
  "ab;if(0!==u.length){for(e=u[0],n=e.length,r=1;r<u.length;r++)"\
  "for(o=u[r],t=0;t<n;t++)if(o[t]!==e[t]){n=t;break}for(r=_.pos;"\
  "r<n;r++)insert(e[r]);if(last_fun===completion&&1===u.length){"\
  "const e=_.ctx[u[0]];\"function\"==typeof e?(insert(\"(\"),0===e.l"\
  "ength&&insert(\")\")):\"object\"==typeof e&&insert(\".\")}if(last_f"\
  "un===completion&&2<=u.length){for(i=0,r=0;r<u.length;r++)i=Ma"\
  "th.max(i,u[r].length);for(i+=2,c=Math.max(1,Math.floor((term_"\
  "width+1)/i)),l=Math.ceil(u.length/c),write(\"\\n\"),a=0;a<l;a++)"\
  "{for(s=0;s<c&&!((r=s*l+a)>=u.length);s++)e=u[r],s!==c-1&&(e=e"\
  ".padEnd(i)),write(e);write(\"\\n\")}readline_print_prompt()}}}co"\
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
  "u\":upcase_word,\"""\x7f""\":backward_delete_char};function dupstr(e"\
  ",r){let t=\"\";for(;0<r--;)t+=e;return t}let readline_keys,read"\
  "line_state,readline_cb;function readline_print_prompt(){write"\
  "(prompt),term_cursor_x=ucs_length(prompt)%term_width,last_cmd"\
  "=\"\",last_cursor_pos=0}function readline_start(e,r){if(cmd=e||"\
  "\"\",cursor_pos=cmd.length,history_index=history.length,readlin"\
  "e_cb=r,prompt=pstate,mexpr)prompt=(prompt+=dupstr(\" \",plen-pr"\
  "ompt.length))+ps2;else{if(show_time){let e=Math.round(eval_ti"\
  "me)+\" \";eval_time=0,e=dupstr(\"0\",5-e.length)+e,prompt+=e.subs"\
  "tring(0,e.length-4)+\".\"+e.substring(e.length-4)}plen=prompt.l"\
  "ength,show_colors&&(prompt+=colors.yellow),prompt+=ps1,show_c"\
  "olors&&(prompt+=colors.none)}readline_print_prompt(),update()"\
  ",readline_state=0}function handle_char(e){var r=String.fromCo"\
  "dePoint(e);switch(readline_state){case 0:\"""\x1b""\"===r?(readline"\
  "_keys=r,readline_state=1):handle_key(r);break;case 1:readline"\
  "_keys+=r,readline_state=\"[\"===r?2:\"O\"===r?3:(handle_key(readl"\
  "ine_keys),0);break;case 2:readline_keys+=r,\";\"===r||\"0\"<=r&&r"\
  "<=\"9\"||(handle_key(readline_keys),readline_state=0);break;cas"\
  "e 3:handle_key(readline_keys+=r),readline_state=0}}function h"\
  "andle_key(e){var r;if(quote_flag)1===ucs_length(e)&&insert(e)"\
  ",quote_flag=!1;else if(r=commands[e]){switch((this_fun=r)(e))"\
  "{case-1:return readline_cb(cmd);case-2:return readline_cb(nul"\
  "l);case-3:return}last_fun=this_fun}else 1===ucs_length(e)&&\" "\
  "\"<=e?(insert(e),last_fun=insert):alert();cursor_pos=cursor_po"\
  "s<0?0:cursor_pos>cmd.length?cmd.length:cursor_pos,update()}le"\
  "t hex_mode=!1,eval_mode=\"std\";function number_to_string(e,r){"\
  "if(isFinite(e)){let t;return 0===e?t=1/e<0?\"-0\":\"0\":16===r&&e"\
  "===Math.floor(e)?(t=e<0?(e=-e,\"-\"):\"\",t+=\"0x\"+e.toString(16))"\
  ":t=e.toString(),t}return e.toString()}function bigfloat_to_st"\
  "ring(e,r){let t;return BigFloat.isFinite(e)?(0===e?t=1/e<0?\"-"\
  "0\":\"0\":16===r?(t=e<0?(e=-e,\"-\"):\"\",t+=\"0x\"+e.toString(16)):t="\
  "e.toString(),\"bigfloat\"==typeof e&&\"math\"!==eval_mode?t+=\"l\":"\
  "\"std\"!==eval_mode&&t.indexOf(\".\")<0&&(16===r&&t.indexOf(\"p\")<"\
  "0||10===r&&t.indexOf(\"e\")<0)&&(t+=\".0\"),t):\"math\"!==eval_mode"\
  "?\"BigFloat(\"+e.toString()+\")\":e.toString()}function bigint_to"\
  "_string(e,r){let t;return 16===r?(t=e<0?(e=-e,\"-\"):\"\",t+=\"0x\""\
  "+e.toString(16)):t=e.toString(),\"std\"===eval_mode&&(t+=\"n\"),t"\
  "}function print(e){const r=[];!function e(t){let n,o,i,s,c;va"\
  "r a=typeof t;if(\"object\"==a)if(null===t)write(t);else if(0<=r"\
  ".indexOf(t))write(\"[circular]\");else if(has_jscalc&&(t instan"\
  "ceof Fraction||t instanceof Complex||t instanceof Mod||t inst"\
  "anceof Polynomial||t instanceof PolyMod||t instanceof Rationa"\
  "lFunction||t instanceof Series))write(t.toString());else{if(r"\
  ".push(t),Array.isArray(t)){for(n=t.length,write(\"[ \"),o=0;o<n"\
  ";o++)if(0!==o&&write(\", \"),o in t?e(t[o]):write(\"<empty>\"),20"\
  "<o){write(\"...\");break}write(\" ]\")}else if(\"RegExp\"===Object."\
  "__getClass(t))write(t.toString());else{for(i=Object.keys(t),n"\
  "=i.length,write(\"{ \"),o=0;o<n;o++)0!==o&&write(\", \"),s=i[o],w"\
  "rite(s,\": \"),e(t[s]);write(\" }\")}r.pop(t)}else\"string\"==a?(79"\
  "<(c=t.__quote()).length&&(c=c.substring(0,75)+'...\"'),write(c"\
  ")):\"number\"==a?write(number_to_string(t,hex_mode?16:10)):\"big"\
  "int\"==a?write(bigint_to_string(t,hex_mode?16:10)):\"bigfloat\"="\
  "=a?write(bigfloat_to_string(t,hex_mode?16:10)):\"bigdecimal\"=="\
  "a?write(t.toString()+\"m\"):\"symbol\"==a?write(String(t)):\"funct"\
  "ion\"==a?write(\"function \"+t.name+\"()\"):write(t)}(e)}function "\
  "extract_directive(e){let r;if(\"\\\\\"!==e[0])return\"\";for(r=1;r<"\
  "e.length&&is_alpha(e[r]);r++);return e.substring(1,r)}functio"\
  "n handle_directive(e,r){let t,n,o;if(\"h\"===e||\"?\"===e||\"help\""\
  "===e)help();else{if(\"load\"===e){let t=r.substring(e.length+1)"\
  ".trim();return t.lastIndexOf(\".\")<=t.lastIndexOf(\"/\")&&(t+=\"."\
  "js\"),0}if(\"x\"===e)hex_mode=!0;else if(\"d\"===e)hex_mode=!1;els"\
  "e if(\"t\"===e)show_time=!show_time;else{if(has_bignum&&\"p\"===e"\
  "){if(1===(t=r.substring(e.length+1).trim().split(\" \")).length"\
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
  "gnum&&\"digits\"===e)return t=r.substring(e.length+1).trim(),(n"\
  "=Math.ceil(parseFloat(t)*log2_10))<BigFloatEnv.precMin||n>Big"\
  "FloatEnv.precMax?write(\"Invalid precision\\n\"):(prec=n,expBits"\
  "=BigFloatEnv.expBitsMax),0;if(has_bignum&&\"mode\"===e)return\"\""\
  "===(t=r.substring(e.length+1).trim())?write(\"Running mode=\"+e"\
  "val_mode+\"\\n\"):\"std\"===t||\"math\"===t?eval_mode=t:write(\"Inval"\
  "id mode\\n\"),0;if(\"clear\"===e)write(\"""\x1b""[H""\x1b""[J\");else if(\"c"\
  "\"===e)show_colors=!show_colors;else{if(\"q\"===e)return running"\
  "=!1,1;if(has_jscalc&&\"a\"===e)algebraicMode=!0;else{if(!has_js"\
  "calc||\"n\"!==e)return write(\"Unknown directive: \"+e+\"\\n\"),0;al"\
  "gebraicMode=!1}}}}return 1}function help(){function e(e){retu"\
  "rn e?\"*\":\" \"}write(\"\\\\h          this help\\n\\\\x         \"+e(h"\
  "ex_mode)+\"hexadecimal number display\\n\\\\c          toggle col"\
  "ors\\n\\\\d         \"+e(!hex_mode)+\"decimal number display\\n\\\\cl"\
  "ear      clear the terminal\\n\"),has_jscalc&&write(\"\\\\a       "\
  "  \"+e(algebraicMode)+\"algebraic mode\\n\\\\n         \"+e(!algebr"\
  "aicMode)+\"numeric mode\\n\"),has_bignum&&(write(\"\\\\p [m [e]]  s"\
  "et the BigFloat precision to 'm' bits\\n\\\\digits n   set the B"\
  "igFloat precision to 'ceil(n*log2(10))' bits\\n\"),has_jscalc||"\
  "write(\"\\\\mode [std|math] change the running mode (current = \""\
  "+eval_mode+\")\\n\")),config_numcalc||write(\"\\\\q          exit\\n"\
  "\")}function eval_and_print(expr){let result;try{\"math\"===eval"\
  "_mode&&(expr='\"use math\"; void 0;'+expr);const now=(new Date)"\
  ".getTime();result=eval(expr),eval_time=(new Date).getTime()-n"\
  "ow,write(colors[styles.result]),print(result),write(\"\\n\"),wri"\
  "te(colors.none),g._=result}catch(e){show_colors&&write(colors"\
  "[styles.error_msg]),e instanceof Error?(console.log(e),e.stac"\
  "k&&write(e.stack)):write(\"Throw: \"),show_colors&&write(colors"\
  ".none)}}function cmd_start(){var e;config_numcalc||(e=has_jsc"\
  "alc?\"QJSCalc\":\"QuickJS\",console.log(e,'- Type \"\\\\h\" for help'"\
  ")),has_bignum&&(log2_10=Math.log(10)/Math.log(2),prec=113,exp"\
  "Bits=15,has_jscalc)&&(eval_mode=\"math\",g.algebraicMode=config"\
  "_numcalc),cmd_readline_start()}function cmd_readline_start(){"\
  "try{readline_start(dupstr(\"    \",level),readline_handle_cmd)}"\
  "catch(e){console.error(\"ERROR\",e)}}function readline_handle_c"\
  "md(e){handle_cmd(e),os.pending(),cmd_readline_start()}functio"\
  "n handle_cmd(e){if(null===e)return\"\";if(\"?\"===e||\"h\"===e)retu"\
  "rn help();var r=extract_directive(e);if(0<r.length){if(!handl"\
  "e_directive(r,e))return;e=e.substring(r.length+1)}\"\"!==e&&(r="\
  "colorize_js(e=mexpr?mexpr+\"\\n\"+e:e),pstate=r[0],level=r[1],ps"\
  "tate?mexpr=e:(mexpr=\"\",has_bignum?BigFloatEnv.setPrec(eval_an"\
  "d_print.bind(null,e),prec,expBits):eval_and_print(e),level=0)"\
  ")}function colorize_js(e){let r,t,n;const o=e.length;let i,s="\
  "\"\",c=0,a=1;const l=[];function _(e){s+=e}function u(){return "\
  "s.substring(s.length-1)}function d(){var e=u();return s=s.sub"\
  "string(0,s.length-1),e}function f(e,r){for(;l.length<e;)l.pus"\
  "h(\"default\");for(;l.length<r;)l.push(i)}for(r=0;r<o;){switch("\
  "i=null,n=r,t=e[r++]){case\" \":case\"\\t\":case\"\\r\":case\"\\n\":conti"\
  "nue;case\"+\":case\"-\":if(r<o&&e[r]===t){r++;continue}a=1;contin"\
  "ue;case\"/\":if(r<o&&\"*\"===e[r]){for(i=\"comment\",_(\"/\"),r++;r<o"\
  "-1;r++)if(\"*\"===e[r]&&\"/\"===e[r+1]){r+=2,d();break}break}if(r"\
  "<o&&\"/\"===e[r]){for(i=\"comment\",r++;r<o&&\"\\n\"!==e[r];r++);bre"\
  "ak}if(a){for(i=\"regex\",_(\"/\");r<o;)if(\"\\n\"!==(t=e[r++]))if(\"\\"\
  "\\\"!==t)if(\"[\"!==u())if(\"[\"!==t){if(\"/\"===t){for(d();r<o&&is_w"\
  "ord(e[r]);)r++;break}}else _(\"[\"),\"[\"!==e[r]&&\"]\"!==e[r]||r++"\
  ";else\"]\"===t&&d();else r<o&&r++;else i=\"error\";a=0;break}a=1;"\
  "continue;case\"'\":case'\"':case\"`\":(function(n){for(i=\"string\","\
  "_(n);r<o;)if(\"\\n\"!==(t=e[r++])){if(\"\\\\\"===t){if(r>=o)break;r+"\
  "+}else if(t===n){d();break}}else i=\"error\"})(t),a=0;break;cas"\
  "e\"(\":case\"[\":case\"{\":a=1,c++,_(t);continue;case\")\":case\"]\":ca"\
  "se\"}\":if((a=0)<c&&is_balanced(u(),t)){c--,d();continue}i=\"err"\
  "or\";break;default:if(is_digit(t)){for(i=\"number\";r<o&&(is_wor"\
  "d(e[r])||\".\"===e[r]&&(r===o-1||\".\"!==e[r+1]));)r++;a=0}else{i"\
  "f(!is_word(t)&&\"$\"!==t){a=1;continue}!function(){for(a=1;r<o&"\
  "&is_word(e[r]);)r++;var t=\"|\"+e.substring(n,r)+\"|\";if(0<=\"|br"\
  "eak|case|catch|continue|debugger|default|delete|do|else|final"\
  "ly|for|function|if|in|instanceof|new|return|switch|this|throw"\
  "|try|typeof|while|with|class|const|enum|import|export|extends"\
  "|super|implements|interface|let|package|private|protected|pub"\
  "lic|static|yield|undefined|null|true|false|Infinity|NaN|eval|"\
  "arguments|await|\".indexOf(t))return i=\"keyword\",0<=\"|this|sup"\
  "er|undefined|null|true|false|Infinity|NaN|arguments|\".indexOf"\
  "(t)&&(a=0);let s=r;for(;s<o&&\" \"===e[s];)s++;s<o&&\"(\"===e[s]?"\
  "i=\"function\":0<=\"|void|var|\".indexOf(t)?i=\"type\":(i=\"identifi"\
  "er\",a=0)}()}}i&&f(n,r)}return f(o,o),[s,c,l]}config_numcalc&&"\
  "(g.execCmd=function(e){switch(e){case\"dec\":hex_mode=!1;break;"\
  "case\"hex\":hex_mode=!0;break;case\"num\":algebraicMode=!1;break;"\
  "case\"alg\":algebraicMode=!0}});try{termInit()}catch(e){console"\
  ".error(e)}}(globalThis)}));\n";
