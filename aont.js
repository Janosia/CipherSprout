class AONT{
    constructor(){
        this.CANARY_SIZE =16;
        this.KEY_SIZE =32;
    }
    async generateKey(){
        return crypto.getRandomValues(new Uint8Array(this.KEY_SIZE));
    }
    async encrypt(data, key, nonce){
        console.log("Encrypting data:", data);
        console.log("Key:", key);
        console.log("Nonce:", nonce);
        
        // Assuming you're using Web Crypto API (for example)
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(data); 
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            {name : 'AES-GCM'},
            false,
            ['encrypt'] 
        );
        const dataWithCanary = new Uint8Array(data.length +this.CANARY_SIZE);
        dataWithCanary.set(encodedData);

        return crypto.subtle.encrypt({
            name:'AES-GCM',
            iv:nonce
        },
        cryptoKey,
        dataWithCanary);
    }
    async  hash(data){
        let arrayBuffer;

        if (data instanceof ArrayBuffer) {
            arrayBuffer = data;
        } else if (data.encryptedDt instanceof ArrayBuffer) {
            arrayBuffer = data.buffer;
        } else if (typeof data === 'string') {
            const encoder = new TextEncoder();
            arrayBuffer = encoder.encode(data).buffer;
        } else {
            throw  Error('Invalid data type. Expected an ArrayBuffer, Uint8Array, or string.');
        }
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);

        // Convert ArrayBuffer to a Hex string (optional)
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
        
        return hashHex;
    }
    XOR_Buffer(key, hash){
        const result = new Uint8Array(key.length);
        for(let i=0; i<key.length; i++){
            result[i]=key[i]^hash[i];
        }
        return result;
    }

    async encode_aont(data){
        const nonce = crypto.getRandomValues(new Uint16Array(12));
        const key = await this.generateKey();

        const encryptedDt = await this.encrypt(data, key, nonce);

        // console.log("here encrypt function is calling hash");
        const hashedData = await this.hash(encryptedDt);

        const difference= this.XOR_Buffer(key, new Uint8Array(hashedData));

        return{
            encryptedDt,difference,nonce
        };
    }
    async decode(encryptedDt, difference, nonce){
        // console.log(encryptedDt);
        console.log("here decrypt function is calling hash");
        const hashedDt = await this.hash(encryptedDt);
        const key = this.XOR_Buffer(difference, new Uint8Array(hashedDt));
        const decryptData = await this.decrypt(encryptedDt, key, nonce);
        return decryptData;
    }

    async decrypt(encryptedData, key, nonce){
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            {name:'AES-GCM'},
            false,
            ['decrypt']
        );

        const decryptedData = await crypto.subtle.decrypt({
            name:'AES-GCM',
            iv : nonce
        },
        cryptoKey,
        encryptedData,);
        // console.log(decryptedData);
    return decryptedData;
    }
}

async function main(){

    const aont = new AONT();
    const ogDATA = "HI I AM JANOSIA";
    console.log(ogDATA);
    const {encryptedDt, difference, nonce} =await aont.encode_aont(ogDATA);
    
    // console.log({encrypted});

    const decrDt = await aont.decode(encryptedDt, difference, nonce);
    console.log(decrDt);
    console.log(new TextDecoder().decode(decrDt));
    
}

main().catch(console.error);
