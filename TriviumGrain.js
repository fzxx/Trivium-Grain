// TriviumGrain.js   https://github.com/fzxx/Trivium-Grain

(function(root,factory){
	if(typeof exports==='object')module.exports=factory();
else root.TriviumGrain=factory();
}
(typeof self!=='undefined'?self:this,function(){
const checkLen=(name,arr,expect)=>{
if(arr.length!==expect){
throw new RangeError(`${name} 需要 ${expect} 位，实际得到 ${arr.length} 位`);
}
};
const _bytesToBitsMSB=(byteArr,bitLen)=>{
const out=new Uint8Array(bitLen);
for(let i=0;i<byteArr.length;i++){
const b=byteArr[i];
for(let j=0;j<8;j++){
out[i*8+j]=(b>>>(7-j))&1;
}
}
return out;
};
const _bitsToBytesMSB=(bitArr)=>{
const byteLen=Math.ceil(bitArr.length/8);
const out=new Uint8Array(byteLen);
for(let i=0;i<bitArr.length;i++){
if(bitArr[i]){
out[Math.floor(i/8)]|=1<<(7-(i%8));
}
}
return out;
};
const swapBitsInByte=(n)=>{
let val=0;
for(let i=0;i<8;i++){
val|=((n>>i)&1)<<(7-i);
}
return val;
};
class Grain128AEADState{
constructor(){
this.lfsr=new Uint8Array(128);
this.nfsr=new Uint8Array(128);
this.auth_acc=new Uint8Array(64);
this.auth_sr=new Uint8Array(64);
this.round=0;
}
}
const GRAIN128_INIT=0;
const GRAIN128_ADDKEY=1;
const GRAIN128_NORMAL=2;
const grain128_lfsr_fb=(lfsr)=>{
return lfsr[96]^lfsr[81]^lfsr[70]^lfsr[38]^lfsr[7]^lfsr[0];
};
const grain128_nfsr_fb=(nfsr)=>{
return nfsr[96]^nfsr[91]^nfsr[56]^nfsr[26]^nfsr[0]^(nfsr[84]&nfsr[68])^(nfsr[67]&nfsr[3])^(nfsr[65]&nfsr[61])^(nfsr[59]&nfsr[27])^(nfsr[48]&nfsr[40])^(nfsr[18]&nfsr[17])^(nfsr[13]&nfsr[11])^(nfsr[82]&nfsr[78]&nfsr[70])^(nfsr[25]&nfsr[24]&nfsr[22])^(nfsr[95]&nfsr[93]&nfsr[92]&nfsr[88]);
};
const grain128_h=(lfsr,nfsr)=>{
const x0=nfsr[12];
const x1=lfsr[8];
const x2=lfsr[13];
const x3=lfsr[20];
const x4=nfsr[95];
const x5=lfsr[42];
const x6=lfsr[60];
const x7=lfsr[79];
const x8=lfsr[94];
return(x0&x1)^(x2&x3)^(x4&x5)^(x6&x7)^(x0&x4&x8);
};
const shiftRegister=(fsr,fb)=>{
const out=fsr[0];
for(let i=0;i<fsr.length-1;i++){
fsr[i]=fsr[i+1];
}
fsr[fsr.length-1]=fb;
return out;
};
const authShift64=(sr,fb)=>{
for(let i=0;i<sr.length-1;i++){
sr[i]=sr[i+1];
}
sr[sr.length-1]=fb;
};
const accumulate=(state)=>{
for(let i=0;i<64;i++){
state.auth_acc[i]^=state.auth_sr[i];
}
};
const grain128_next_z=(state,keybit=0,keybit64=0)=>{
const lfsr_fb=grain128_lfsr_fb(state.lfsr);
const nfsr_fb=grain128_nfsr_fb(state.nfsr);
const h_out=grain128_h(state.lfsr,state.nfsr);
const A=[2,15,36,45,64,73,89];
let nfsr_tmp=0;
for(let i=0;i<7;i++){
nfsr_tmp^=state.nfsr[A[i]];
}
const y=h_out^state.lfsr[93]^nfsr_tmp;
let lfsr_out;
if(state.round===GRAIN128_INIT){
lfsr_out=shiftRegister(state.lfsr,lfsr_fb^y);
shiftRegister(state.nfsr,nfsr_fb^lfsr_out^y);
}
else if(state.round===GRAIN128_ADDKEY){
lfsr_out=shiftRegister(state.lfsr,lfsr_fb^y^keybit64);
shiftRegister(state.nfsr,nfsr_fb^lfsr_out^y^keybit);
}
else{
lfsr_out=shiftRegister(state.lfsr,lfsr_fb);
shiftRegister(state.nfsr,nfsr_fb^lfsr_out);
}
return y;
};
const encodeDERLength=(len)=>{
if(len<128){
return new Uint8Array([swapBitsInByte(len)]);
}
let len_tmp=len;
let der_len=0;
while(len_tmp>0){
len_tmp>>=8;
der_len++;
}
const result=new Uint8Array(der_len+1);
result[0]=swapBitsInByte(0x80|der_len);
len_tmp=len;
for(let i=der_len;i>0;i--){
result[i]=swapBitsInByte(len_tmp&0xff);
len_tmp>>=8;
}
return result;
};
const initGrain128AEAD=(keyBits,ivBits)=>{
const state=new Grain128AEADState();
for(let i=0;i<96;i++){
state.lfsr[i]=ivBits[i];
}
for(let i=96;i<127;i++){
state.lfsr[i]=1;
}
state.lfsr[127]=0;
for(let i=0;i<128;i++){
state.nfsr[i]=keyBits[i];
}
for(let i=0;i<64;i++){
state.auth_acc[i]=0;
state.auth_sr[i]=0;
}
state.round=GRAIN128_INIT;
for(let i=0;i<320;i++){
grain128_next_z(state,0,0);
}
state.round=GRAIN128_ADDKEY;
for(let i=0;i<64;i++){
grain128_next_z(state,keyBits[i],keyBits[64+i]);
}
state.round=GRAIN128_NORMAL;
for(let i=0;i<64;i++){
state.auth_acc[i]=grain128_next_z(state,0,0);
}
for(let i=0;i<64;i++){
state.auth_sr[i]=grain128_next_z(state,0,0);
}
return state;
};
const initData=(dataBytes)=>{
const bitLen=dataBytes.length*8+1;
const bits=new Uint8Array(bitLen);
for(let i=0;i<dataBytes.length;i++){
const b=dataBytes[i];
for(let j=0;j<8;j++){
bits[i*8+j]=(b>>>(7-j))&1;
}
}
bits[bitLen-1]=1;
return bits;
};
const grain128aead_encrypt=(key,iv,plaintext,associatedData=new Uint8Array(0))=>{
const keySwapped=new Uint8Array(key.length);
const ivSwapped=new Uint8Array(iv.length);
const ptSwapped=new Uint8Array(plaintext.length);
const adSwapped=new Uint8Array(associatedData.length);
for(let i=0;i<key.length;i++)keySwapped[i]=swapBitsInByte(key[i]);
for(let i=0;i<iv.length;i++)ivSwapped[i]=swapBitsInByte(iv[i]);
for(let i=0;i<plaintext.length;i++)ptSwapped[i]=swapBitsInByte(plaintext[i]);
for(let i=0;i<associatedData.length;i++)adSwapped[i]=swapBitsInByte(associatedData[i]);
const keyBits=_bytesToBitsMSB(keySwapped,128);
const ivBits=_bytesToBitsMSB(ivSwapped,96);
const state=initGrain128AEAD(keyBits,ivBits);
const ader=encodeDERLength(associatedData.length);
const adData=new Uint8Array(ader.length+adSwapped.length);
adData.set(ader);
adData.set(adSwapped,ader.length);
let adBitCnt=0;
for(let i=0;i<adData.length;i++){
for(let j=0;j<16;j++){
const z=grain128_next_z(state,0,0);
if(j%2===1){
const adVal=(adData[Math.floor(adBitCnt/8)]>>(7-(adBitCnt%8)))&1;
if(adVal){
accumulate(state);
}
authShift64(state.auth_sr,z);
adBitCnt++;
}
}
}
const plaintextBits=initData(ptSwapped);
const ciphertext=new Uint8Array(plaintext.length+8);
let msgBitCnt=0;
let authBitCnt=0;
let cipherByteCnt=0;
for(let i=0;i<plaintext.length;i++){
let cipherByte=0;
for(let j=0;j<16;j++){
const z=grain128_next_z(state,0,0);
if(j%2===0){
const plainBit=plaintextBits[msgBitCnt];
cipherByte|=(plainBit^z)<<(7-(cipherByteCnt%8));
msgBitCnt++;
cipherByteCnt++;
}
else{
if(plaintextBits[authBitCnt]){
accumulate(state);
}
authShift64(state.auth_sr,z);
authBitCnt++;
}
}
ciphertext[i]=swapBitsInByte(cipherByte);
}
grain128_next_z(state,0,0);
accumulate(state);
for(let i=0;i<8;i++){
let tagByte=0;
for(let j=0;j<8;j++){
tagByte|=state.auth_acc[i*8+j]<<(7-j);
}
ciphertext[plaintext.length+i]=swapBitsInByte(tagByte);
}
return ciphertext;
};
const grain128aead_decrypt=(key,iv,ciphertext,associatedData=new Uint8Array(0))=>{
if(ciphertext.length<8){
throw new Error('密文长度至少为8字节（包含标签）');
}
const keySwapped=new Uint8Array(key.length);
const ivSwapped=new Uint8Array(iv.length);
const ctSwapped=new Uint8Array(ciphertext.length);
const adSwapped=new Uint8Array(associatedData.length);
for(let i=0;i<key.length;i++)keySwapped[i]=swapBitsInByte(key[i]);
for(let i=0;i<iv.length;i++)ivSwapped[i]=swapBitsInByte(iv[i]);
for(let i=0;i<ciphertext.length;i++)ctSwapped[i]=swapBitsInByte(ciphertext[i]);
for(let i=0;i<associatedData.length;i++)adSwapped[i]=swapBitsInByte(associatedData[i]);
const keyBits=_bytesToBitsMSB(keySwapped,128);
const ivBits=_bytesToBitsMSB(ivSwapped,96);
const state=initGrain128AEAD(keyBits,ivBits);
const ader=encodeDERLength(associatedData.length);
const adData=new Uint8Array(ader.length+adSwapped.length);
adData.set(ader);
adData.set(adSwapped,ader.length);
let adBitCnt=0;
for(let i=0;i<adData.length;i++){
for(let j=0;j<16;j++){
const z=grain128_next_z(state,0,0);
if(j%2===1){
const adVal=(adData[Math.floor(adBitCnt/8)]>>(7-(adBitCnt%8)))&1;
if(adVal){
accumulate(state);
}
authShift64(state.auth_sr,z);
adBitCnt++;
}
}
}
const plaintext=new Uint8Array(ciphertext.length-8);
const ciphertextBits=initData(ctSwapped);
let cipherBitCnt=0;
let authBitCnt=0;
let cipherBytePos=0;
for(let i=0;i<plaintext.length;i++){
let plainByte=0;
for(let j=0;j<8;j++){
const z1=grain128_next_z(state,0,0);
const cipherBit=ciphertextBits[cipherBitCnt];
const plainBit=cipherBit^z1;
plainByte|=plainBit<<(7-j);
cipherBitCnt++;
const z2=grain128_next_z(state,0,0);
if(plainBit){
accumulate(state);
}
authShift64(state.auth_sr,z2);
authBitCnt++;
}
plaintext[i]=swapBitsInByte(plainByte);
}
grain128_next_z(state,0,0);
accumulate(state);
let tagValid=true;
const tagStartBit=8*(ciphertext.length-8);
for(let i=0;i<64;i++){
const tagBit=ciphertextBits[tagStartBit+i];
if(state.auth_acc[i]!==tagBit){
tagValid=false;
break;
}
}
if(!tagValid){
throw new Error('认证失败：标签不匹配');
}
return plaintext;
};
function triviumCore(key,iv,rounds){
const state=new Uint8Array(288);
for(let i=0;i<80;i++){
state[i]=key[i];
}
for(let i=0;i<80;i++){
state[i+93]=iv[i];
}
state[285]=1;
state[286]=1;
state[287]=1;
for(let i=0;i<rounds;i++){
_triviumRound(state);
}
return state;
}
function _triviumRound(state){
const output=state[65]^state[92]^state[161]^state[176]^state[242]^state[287];
const t1=state[65]^((state[90]&&state[91])?1:0)^state[92]^state[170];
const t2=state[161]^((state[174]&&state[175])?1:0)^state[176]^state[263];
const t3=state[242]^((state[285]&&state[286])?1:0)^state[287]^state[68];
const newState=new Uint8Array(288);
newState[0]=t3;
for(let i=0;i<92;i++){
newState[i+1]=state[i];
}
newState[93]=t1;
for(let i=93;i<176;i++){
newState[i+1]=state[i];
}
newState[177]=t2;
for(let i=177;i<287;i++){
newState[i+1]=state[i];
}
for(let i=0;i<288;i++){
state[i]=newState[i];
}
return output;
}
function*triviumKeystreamGen(key,iv){
const state=triviumCore(key,iv,1152);
while(true){
let byte=0;
for(let i=0;i<8;i++){
byte=(byte<<1)|_triviumRound(state);
}
yield byte;
}
}
const N=(state,i)=>state.NFSR[80-i];
const L=(state,i)=>state.LFSR[80-i];
class GrainV1State{
constructor(){
this.LFSR=new Uint8Array(80);
this.NFSR=new Uint8Array(80);
this.p_key=null;
this.keysize=80;
this.ivsize=64;
}
}
const grain_keystream=(state)=>{
const X0=state.LFSR[3];
const X1=state.LFSR[25];
const X2=state.LFSR[46];
const X3=state.LFSR[64];
const X4=state.NFSR[63];
const outbit=N(state,79)^N(state,78)^N(state,76)^N(state,70)^N(state,49)^N(state,37)^N(state,24)^X1^X4^(X0&X3)^(X2&X3)^(X3&X4)^(X0&X1&X2)^(X0&X2&X3)^(X0&X2&X4)^(X1&X2&X4)^(X2&X3&X4);
const NBit=L(state,80)^N(state,18)^N(state,20)^N(state,28)^N(state,35)^N(state,43)^N(state,47)^N(state,52)^N(state,59)^N(state,66)^N(state,71)^N(state,80)^(N(state,17)&N(state,20))^(N(state,43)&N(state,47))^(N(state,65)&N(state,71))^(N(state,20)&N(state,28)&N(state,35))^(N(state,47)&N(state,52)&N(state,59))^(N(state,17)&N(state,35)&N(state,52)&N(state,71))^(N(state,20)&N(state,28)&N(state,43)&N(state,47))^(N(state,17)&N(state,20)&N(state,59)&N(state,65))^(N(state,17)&N(state,20)&N(state,28)&N(state,35)&N(state,43))^(N(state,47)&N(state,52)&N(state,59)&N(state,65)&N(state,71))^(N(state,28)&N(state,35)&N(state,43)&N(state,47)&N(state,52)&N(state,59));
const LBit=L(state,18)^L(state,29)^L(state,42)^L(state,57)^L(state,67)^L(state,80);
for(let i=1;i<state.keysize;++i){
state.NFSR[i-1]=state.NFSR[i];
state.LFSR[i-1]=state.LFSR[i];
}
state.NFSR[state.keysize-1]=NBit;
state.LFSR[state.keysize-1]=LBit;
return outbit;
};
const grain_keysetup=(state,key,keysize,ivsize)=>{
state.p_key=key;
state.keysize=keysize;
state.ivsize=ivsize;
};
const grain_ivsetup=(state,iv)=>{
for(let i=0;i<Math.floor(state.ivsize/8);++i){
for(let j=0;j<8;++j){
state.NFSR[i*8+j]=(state.p_key[i]>>j)&1;
state.LFSR[i*8+j]=(iv[i]>>j)&1;
}
}
for(let i=Math.floor(state.ivsize/8);i<Math.floor(state.keysize/8);++i){
for(let j=0;j<8;++j){
state.NFSR[i*8+j]=(state.p_key[i]>>j)&1;
state.LFSR[i*8+j]=1;
}
}
const INITCLOCKS=160;
for(let i=0;i<INITCLOCKS;++i){
const outbit=grain_keystream(state);
state.LFSR[79]^=outbit;
state.NFSR[79]^=outbit;
}
};
const grain_keystream_bytes=(state,msglen)=>{
const keystream=new Uint8Array(msglen);
for(let i=0;i<msglen;++i){
let byte=0;
for(let j=0;j<8;++j){
byte|=(grain_keystream(state)<<j);
}
keystream[i]=byte;
}
return keystream;
};
const grain_encrypt_bytes=(state,plaintext)=>{
const ciphertext=new Uint8Array(plaintext.length);
for(let i=0;i<plaintext.length;++i){
let k=0;
for(let j=0;j<8;++j){
k|=(grain_keystream(state)<<j);
}
ciphertext[i]=plaintext[i]^k;
}
return ciphertext;
};
const grain_decrypt_bytes=(state,ciphertext)=>{
return grain_encrypt_bytes(state,ciphertext);
};
function grainCore(key,iv,rounds){
const keyBytes=new Uint8Array(Math.ceil(key.length/8));
const ivBytes=new Uint8Array(Math.ceil(iv.length/8));
for(let i=0;i<key.length;i++){
if(key[i]){
keyBytes[Math.floor(i/8)]|=1<<(i%8);
}
}
for(let i=0;i<iv.length;i++){
if(iv[i]){
ivBytes[Math.floor(i/8)]|=1<<(i%8);
}
}
const state=new GrainV1State();
grain_keysetup(state,keyBytes,80,64);
grain_ivsetup(state,ivBytes);
return state;
}
function*grainKeystreamGen(key,iv){
const state=grainCore(key,iv,160);
while(true){
let byte=0;
for(let i=0;i<8;i++){
byte|=(grain_keystream(state)<<i);
}
yield byte;
}
}
return{
encrypt:function(algo,key,iv,plaintext,associatedData){
associatedData=associatedData||new Uint8Array(0);
if(algo==='trivium'){
checkLen('Trivium 密钥',key,80);
checkLen('Trivium IV',iv,80);
}
else if(algo==='grain'){
checkLen('Grain 密钥',key,80);
checkLen('Grain IV',iv,64);
}
else if(algo==='grain128aead'){
if(key.length!==16)throw new RangeError('Grain128AEAD 密钥需要 16 字节（128位）');
if(iv.length!==12)throw new RangeError('Grain128AEAD IV 需要 12 字节（96位）');
}
else{
throw new TypeError(`不支持的算法: ${algo}`);
}
const startTime=performance.now();
let out;
if(algo==='grain128aead'){
out=grain128aead_encrypt(key,iv,plaintext,associatedData);
}
else{
const pt=(typeof plaintext==='string')?new TextEncoder().encode(plaintext):plaintext;
const gen=algo==='trivium'?triviumKeystreamGen(key,iv):grainKeystreamGen(key,iv);
out=new Uint8Array(pt.length);
for(let i=0;i<pt.length;i++){
out[i]=pt[i]^gen.next().value;
}
}
const endTime=performance.now();
console.log(`${algo} 处理耗时: ${(endTime - startTime).toFixed(2)} 毫秒`);
return out;
},
decrypt:function(algo,key,iv,ciphertext,associatedData){
associatedData=associatedData||new Uint8Array(0);
if(algo==='grain128aead'){
return grain128aead_decrypt(key,iv,ciphertext,associatedData);
}
else{
return this.encrypt(algo,key,iv,ciphertext,associatedData);
}
},
swapBitsInByte,bytesToBitsMSB:_bytesToBitsMSB,
bitsToBytesMSB:_bitsToBytesMSB,
triviumKeystreamGen,
grainKeystreamGen,
grain128aead_encrypt,
grain128aead_decrypt,
initGrain128AEAD,
encodeDERLength,
grain_keystream,
grain_keysetup,
grain_ivsetup,
grain_keystream_bytes,
grain_encrypt_bytes,
grain_decrypt_bytes
};
})
);