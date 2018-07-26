## iOS webkit中window.crypto.getRandomValues()随机种子的生成

今天被问及以太坊钱包的安全性相关的问题，主要涉及私钥随机种子的产生，以及随机数生成器;
在keythereum源码中，看到randomBytes的实现是通过调用window.crypto.getRandomValues来实现，代码片段如下

```
function randomBytes(size, cb) {
    if (size > 65536)
        throw new Error("requested too many random bytes");
    var rawBytes = new global.Uint8Array(size);
    if (size > 0) {
        crypto.getRandomValues(rawBytes)
    }
    var bytes = new Buffer(rawBytes.buffer);
    if (typeof cb === "function") {
        return process.nextTick(function() {
            cb(null, bytes)
        })
    }
    return bytes
    
    
}

```


前往[webkit](https://github.com/WebKit/webkit/blob/c7c6818a1e4efbf7acb188d1248401a6ec3e08e0/Source/WebCore/page/Crypto.cpp)源码查看对应的C++实现


```
ExceptionOr<void> Crypto::getRandomValues(ArrayBufferView& array)
{
    if (!isInt(array.getType()))
        return Exception { TypeMismatchError };
    if (array.byteLength() > 65536)
        return Exception { QuotaExceededError };
#if OS(DARWIN)
    int rc = CCRandomCopyBytes(kCCRandomDefault, array.baseAddress(), array.byteLength());
    RELEASE_ASSERT(rc == kCCSuccess);
#else
    cryptographicallyRandomValues(array.baseAddress(), array.byteLength());
#endif
    return { };
}

```

其中对于DARWIN系统调用了CCRandomCopyBytes，于是进一步查找到[CommonRandom.c](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60026/Source/API/CommonRandom.c)对应的实现

```
int CCRandomCopyBytes(CCRandomRef rnd, void *bytes, size_t count)
{	
	//定义结构体时，调用了ccrng_system_init()
    struct ccrng_state *rng;
    
    CC_DEBUG_LOG(ASL_LEVEL_ERR, "Entering rnd(NULL) = %s\n", (rnd == NULL) ? "TRUE": "FALSE");

    
    if(NULL == bytes) return -1;
    if(0 == count) return 0;
    if(NULL == rnd) {
        rng = ccDRBGGetRngState();
        return ccDRBGReadBytes(rng, bytes, count);
    }
    
    switch(rnd->rngtype) {
        case rng_default:
            rng = ccDRBGGetRngState();
            return ccDRBGReadBytes(rng, bytes, count);
            break;
        case rng_devrandom:
            rng = ccDevRandomGetRngState();
            return ccDevRandomReadBytes(bytes, count);
            break;
        case rng_created:
            return ccDRBGReadBytes(rnd->state.drbg, bytes, count);
            break;
        default: // we can get bytes from the DRBG
            rng = ccDRBGGetRngState();
            return ccDRBGReadBytes(rng, bytes, count);
            break;
    }
}
```

在定义结构体时，调用了ccrng_system_init()

```
struct ccrng_state *
ccDevRandomGetRngState()
{
    static dispatch_once_t rnginit;
    dispatch_once(&rnginit, ^{        
        kCCRandomDevRandom->state.devrandom = (struct ccrng_state *) CC_XMALLOC(sizeof(struct ccrng_system_state));
        //调用ccrng_system_init
        ccrng_system_init(kCCRandomDevRandom->state.devrandom);
        
    });
    return kCCRandomDevRandom->state.devrandom;
}

```


其中看到了ccrng_CommonCrypto_init,继续跟踪查找找到了[ccrng_system.h]
(https://opensource.apple.com/source/xnu/xnu-3248.60.10/EXTERNAL_HEADERS/corecrypto/ccrng_system.h.auto.html)

```
// Setup the system RNG (open descriptor on file /dev/random)
int ccrng_system_init(struct ccrng_system_state *rng);
```

终于找到了随机数的来源 /dev/random，其中最后在CCRandomCopyBytes函数内调用的ccDRBGGetRngState(); ccDRBGReadBytes()的实现在也是在CommonRandom.c文件内

###[ccrng ](https://www.researchgate.net/publication/225201997_Random_number_generation_using_a_chaotic_circuit)
的缩写是 chaotic circuit based RNG

但在网上看到一篇[论文](http://mista.nu/research/early_random-paper.pdf)讨论了在iOS6／iOS7内核实现的伪随机数存在被攻击的可能.

###题外话
[SecRandomCopyBytes](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes)
这个函数是Security framework的一个API，其实也是调用的[CCRandomCopyBytes](https://opensource.apple.com/source/Security/Security-55471/libsecurity_keychain/lib/SecRandom.c)这个方法

```
int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes) {
    if (rnd != kSecRandomDefault)
        return errSecParam;
    return CCRandomCopyBytes(kCCRandomDefault, bytes, count);
}
```

[安全性](https://stackoverflow.com/questions/21734909/is-os-xs-secrandomcopybytes-fork-safe)
[官网说明](https://developer.apple.com/documentation/security/randomization_services)


