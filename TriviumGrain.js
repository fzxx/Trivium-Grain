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
			else{
				throw new TypeError(`不支持的算法: ${algo}`);
			}
			const startTime=performance.now();
			const pt=(typeof plaintext==='string')?new TextEncoder().encode(plaintext):plaintext;
			const gen=algo==='trivium'?triviumKeystreamGen(key,iv):grainKeystreamGen(key,iv);
			const out=new Uint8Array(pt.length);
			for(let i=0;i<pt.length;i++){
				out[i]=pt[i]^gen.next().value;
			}
			const endTime=performance.now();
			console.log(`${algo} 处理耗时: ${(endTime - startTime).toFixed(2)} 毫秒`);
			return out;
		},
		decrypt:function(algo,key,iv,ciphertext,associatedData){
			associatedData=associatedData||new Uint8Array(0);
			return this.encrypt(algo,key,iv,ciphertext,associatedData);
		},
		swapBitsInByte,bytesToBitsMSB:_bytesToBitsMSB,
		bitsToBytesMSB:_bitsToBytesMSB,
		triviumKeystreamGen,
		grainKeystreamGen,
		grain_keystream,
		grain_keysetup,
		grain_ivsetup,
		grain_keystream_bytes,
		grain_encrypt_bytes,
		grain_decrypt_bytes
	};
})
);