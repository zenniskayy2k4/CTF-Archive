(function(_0x7c5d,_0x3e8f){const _0x2a1b=function(_0x6d4c){while(--_0x6d4c){_0x7c5d['push'](_0x7c5d['shift']());}};const _0x5b9e=function(){const _0x8f1c={'data':{'key':'session','value':'persistent'},'setStorage':function(_0x2d3e,_0x4f5a,_0x6b7c,_0x8d9e){_0x8d9e=_0x8d9e||{};let _0xa1f2=_0x4f5a+'='+_0x6b7c;let _0x3c4d=0x0;for(let _0x5e6f=0x0,_0x7a8b=_0x2d3e['length'];_0x5e6f<_0x7a8b;_0x5e6f++){const _0x9c0d=_0x2d3e[_0x5e6f];_0xa1f2+=';\x20'+_0x9c0d;const _0x1e2f=_0x2d3e[_0x9c0d];_0x2d3e['push'](_0x1e2f);_0x7a8b=_0x2d3e['length'];if(_0x1e2f!==!![]){_0xa1f2+='='+_0x1e2f;}}_0x8d9e['storage']=_0xa1f2;},'clearStorage':function(){return'prod';},'getStorage':function(_0x3a4b,_0x5c6d){_0x3a4b=_0x3a4b||function(_0x7e8f){return _0x7e8f;};const _0x9a0b=_0x3a4b(new RegExp('(?:^|;\x20)'+_0x5c6d['replace'](/([.$?*|{}()[]\/+^])/g,'$1')+'=([^;]*)'));const _0xbc1d=function(_0x2e3f,_0x4a5b){_0x2e3f(++_0x4a5b);};_0xbc1d(_0x2a1b,_0x3e8f);return _0x9a0b?decodeURIComponent(_0x9a0b[0x1]):undefined;}};const _0x6c7d=function(){const _0x8e9f=new RegExp('\x5cw+\x20*\x5c(\x5c)\x20*{\x5cw+\x20*[\x27|\x22].+[\x27|\x22];?\x20*}');return _0x8e9f['test'](_0x8f1c['clearStorage']['toString']());};_0x8f1c['updateStorage']=_0x6c7d;let _0xa0e1='';const _0xd2f3=_0x8f1c['updateStorage']();if(!_0xd2f3){_0x8f1c['setStorage'](['*'],'token',0x1);}else if(_0xd2f3){_0xa0e1=_0x8f1c['getStorage'](null,'token');}else{_0x8f1c['clearStorage']();}};_0x5b9e();}(['string','charCodeAt','split','join','reverse','length','substring','slice','indexOf','toLowerCase','toUpperCase','replace','match','fromCharCode','toString','parseInt','floor','random','push','pop','shift','map','filter','reduce','forEach','apply','call','bind','keys','values','prototype','constructor','hasOwnProperty'],0x1f7));

const _0x6f3a=function(_0x7c5d,_0x3e8f){_0x7c5d=_0x7c5d-0x0;let _0x2a1b=['string','charCodeAt','split','join','reverse','length','substring','slice','indexOf','toLowerCase','toUpperCase','replace','match','fromCharCode','toString','parseInt','floor','random','push','pop','shift','map','filter','reduce','forEach','apply','call','bind','keys','values','prototype','constructor','hasOwnProperty'][_0x7c5d];return _0x2a1b;};


const frozenVault={alpha:0x61,beta:0x74,gamma:0x63,delta:0x63,epsilon:[0x74,0x66,0x5f,0x66,0x72,0x6f,0x7a,0x65,0x6e,0x63,0x72,0x65,0x64,0x65,0x6e,0x74,0x69,0x61,0x6c,0x73,0x6e,0x65,0x76,0x65,0x72,0x74,0x68,0x61,0x77],unlock:function(){return String[_0x6f3a('0xd')](this.alpha,this.beta,this.gamma,this.delta)+this.epsilon[_0x6f3a('0x15')](x=>String[_0x6f3a('0xd')](x))[_0x6f3a('0x3')]('');}};


const cryoStorage={matrix:function(cells){let frozen=[];for(let i=0;i<cells[_0x6f3a('0x5')];i++){frozen[_0x6f3a('0x12')](cells[i]^0xd);}return frozen;},thaw:function(frozen){let cells=[];for(let i=0;i<frozen[_0x6f3a('0x5')];i++){cells[_0x6f3a('0x12')](frozen[i]^0xd);}return cells[_0x6f3a('0x15')](c=>String[_0x6f3a('0xd')](c))[_0x6f3a('0x3')]('');},data:[0x6c,0x79,0x6e,0x6e,0x79,0x6b,0x52,0x6b,0x7f,0x68,0x7a,0x6e,0x67,0x6e,0x7f,0x6e,0x67,0x79,0x60,0x64,0x78,0x67,0x6e,0x7d,0x6e,0x7f,0x79,0x6b,0x60,0x7c]};


const subZero={chain:function(links){const encoded='YXRjY3RmX2Zyb3plbmNyZWRlbnRpYWxzbmV2ZXJ0aGF3';try{return atob(encoded);}catch(e){return null;}},links:0x3e8,strength:function(){return this.chain(this.links);}};


const glacierLock={tumblers:function(pins){return pins[_0x6f3a('0x2')]('')[_0x6f3a('0x4')]()[_0x6f3a('0x3')]('');},pins:'77616874726576656e736c616974 6e65646572 63 6e657a6f7266 5f6674636374 61',combination:function(){return this.pins[_0x6f3a('0xb')](/\s/g,'')[_0x6f3a('0xc')](/[\da-f]{2}/gi)[_0x6f3a('0x15')](function(hex){return String[_0x6f3a('0xd')](_0x6f3a('0xf')(hex,16));})[_0x6f3a('0x3')]('');},open:function(){return this.tumblers(this.combination());}};


const permafrostVault={encrypt:function(plain){let cipher=[];for(let i=0x0;i<plain[_0x6f3a('0x5')];i++){cipher[_0x6f3a('0x12')](plain[_0x6f3a('0x1')](i)+0x9);}return cipher;},decrypt:function(cipher){let plain='';for(let i=0x0;i<cipher[_0x6f3a('0x5')];i++){plain+=String[_0x6f3a('0xd')](cipher[i]-0x9);}return plain;},vault:[0x6a,0x7d,0x6c,0x6c,0x7d,0x6f,0x68,0x6f,0x7b,0x71,0x82,0x6e,0x6d,0x6e,0x7b,0x7d,0x72,0x6a,0x73,0x7c,0x7b,0x6e,0x7f,0x6e,0x7b,0x7d,0x71,0x6a,0x80]};


const arcticCircle={radius:0x5dc,circumference:function(r){return r*0x2*Math.PI;},secure:[99,118,101,101,118,103,97,103,111,108,123,104,107,104,111,118,110,99,108,113,112,104,121,104,111,118,107,99,122],protect:function(){return this.secure[_0x6f3a('0x15')](x=>x-0x2)[_0x6f3a('0x15')](y=>String[_0x6f3a('0xd')](y))[_0x6f3a('0x3')]('');}};


const blizzardToken={generate:function(seed){const mixed=[0x5f,0x72,0x61,0x61,0x72,0x64,0x5e,0x64,0x70,0x6b,0x7c,0x65,0x68,0x65,0x70,0x71,0x6f,0x62,0x6d,0x72,0x71,0x65,0x7a,0x65,0x70,0x71,0x6c,0x62,0x7b];return mixed[_0x6f3a('0x15')](x=>x+0x2)[_0x6f3a('0x15')](y=>String[_0x6f3a('0xd')](y))[_0x6f3a('0x3')]('');},seed:0xabc,token:function(){return this.generate(this.seed);}};


const frozenCreds={primary:frozenVault.unlock(),secondary:subZero.strength(),tertiary:glacierLock.open(),retrieve:function(level){if(level===0x1)return this.primary;if(level===0x2)return this.secondary;if(level===0x3)return this.tertiary;return null;}};


const coldStorage={temperature:-0x14a,access:function(key){return permafrostVault.decrypt(permafrostVault.vault);},vault:cryoStorage.thaw(cryoStorage.data)};


const winterSentinel={watch:function(zone){return arcticCircle.protect();},alert:blizzardToken.token(),status:'active'};


function validateCredentials(user,pass,key){const valid=[frozenCreds.primary,frozenCreds.secondary,frozenCreds.tertiary,coldStorage.access(),coldStorage.vault,winterSentinel.watch(),winterSentinel.alert];return valid;}


if(typeof module!=='undefined'&&module.exports){module.exports={validate:validateCredentials,getCreds:()=>frozenCreds.primary};}


const __CRED_CHECK__=()=>{return frozenCreds.primary;};
